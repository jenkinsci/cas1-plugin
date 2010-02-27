/*
 * The MIT License
 *
 * Copyright (c) 2004-2009, Sun Microsystems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package edu.hawaii.its.hudson.security;

import groovy.lang.GroovyShell;
import groovy.lang.Script;
import hudson.Extension;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.ChainedServletFilter;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.commons.lang.StringUtils;
import org.codehaus.groovy.control.CompilationFailedException;
import org.jasig.cas.client.authentication.AttributePrincipalImpl;
import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.*;
import org.kohsuke.stapler.*;
import org.springframework.web.util.UrlPathHelper;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * {@link hudson.security.SecurityRealm} that uses CAS authentication protocol version 1.
 * This is the plain text protocol that UH extended with affiliation details.
 * This implementation doesn't use Acegi because it doesn't look like Acegi supports version 1;
 * Acegi uses only the CAS version 2 client with XML and proxy tickets.
 *
 * @author jbeutel@hawaii.edu
 */
public class Cas1SecurityRealm extends SecurityRealm {
    private static final String AUTH_KEY = "AUTH_KEY";

    public final String casServerUrl;
    public final String hudsonHostName;
    public final Boolean forceRenewal;
    public final String rolesValidationScript;
    public final String testValidationResponse; // not used, but stored for the convenience of future testing
    private transient Script parsedScript = null; // lazy cache, but avoid marshalling

    @DataBoundConstructor
    public Cas1SecurityRealm(String casServerUrl, String hudsonHostName, Boolean forceRenewal, String rolesValidationScript, String testValidationResponse) {
        if (testValidationResponse == null) {
            testValidationResponse = "";
        }
        this.testValidationResponse = testValidationResponse; // no trimming; allow test of spaces
        this.casServerUrl = Util.fixEmptyAndTrim(casServerUrl);
        this.hudsonHostName = Util.fixEmptyAndTrim(hudsonHostName);
        this.rolesValidationScript = normalizeRolesValidationScript(rolesValidationScript);
        this.forceRenewal = forceRenewal;
    }

//    @Override
//    public boolean canLogOut() {
//        return false; // hides the log out link, because CAS will just log right back in again
//    }

    // This makes the log out link work, and is handy for testing, but I don't like loosing my single sign-on.

    @Override
    protected String getPostLogOutUrl(StaplerRequest req, Authentication auth) {
        return casServerUrl + "/logout";
    }

    private static String normalizeRolesValidationScript(String rolesValidationScript) {
        rolesValidationScript = Util.fixEmptyAndTrim(rolesValidationScript);
        if (rolesValidationScript == null) {
            rolesValidationScript = "return []";
        }
        return rolesValidationScript;
    }

    private synchronized Script getParsedScript() {
        if (parsedScript == null) {
            parsedScript = new GroovyShell().parse(rolesValidationScript);
        }
        return parsedScript;
    }

    @Override
    public Filter createFilter(FilterConfig filterConfig) {
        AuthenticationFilter authenticationFilter = new AuthenticationFilter();
        authenticationFilter.setIgnoreInitConfiguration(true); // configuring here, not in web.xml
        authenticationFilter.setRenew(forceRenewal);
        authenticationFilter.setGateway(false);
        authenticationFilter.setCasServerLoginUrl(casServerUrl + "/login");
        authenticationFilter.setServerName(hudsonHostName);

        Cas10TicketValidationFilter validationFilter = new Cas10TicketValidationFilter();
        validationFilter.setIgnoreInitConfiguration(true); // configuring here, not in web.xml
        validationFilter.setRedirectAfterValidation(true);
        validationFilter.setServerName(hudsonHostName);
        validationFilter.setTicketValidator(
                new AbstractCasProtocolUrlBasedTicketValidator(casServerUrl) {

                    protected String getUrlSuffix() {
                        return "validate"; // version 1 protocol
                    }

                    protected Assertion parseResponseFromServer(final String response) throws TicketValidationException {
                        if (!response.startsWith("yes")) {
                            throw new TicketValidationException("CAS could not validate ticket.");
                        }

                        try {
                            final BufferedReader reader = new BufferedReader(new StringReader(response));
                            String mustBeYes = reader.readLine();
                            assert mustBeYes.equals("yes") : mustBeYes;
                            String username = reader.readLine();

                            // parse optional extra validation attributes
                            Collection roles = parseRolesFromValidationResponse(getParsedScript(), response);

                            Map<String, Object> attributes = new HashMap<String, Object>();
                            attributes.put(AUTH_KEY, new Cas1Authentication(username, roles)); // Acegi Authentication
                            // CAS saves this Assertion in the session; we'll use the Authentication it's carrying.
                            return new AssertionImpl(new AttributePrincipalImpl(username), attributes);
                        }
                        catch (final IOException e) {
                            throw new TicketValidationException("Unable to parse CAS response.", e);
                        }
                    }
                }
        );

        Filter casToAcegiContext = new OnlyDoFilter() {
            /**
             * Gets the authentication out of the session and puts it in Acegi's ThreadLocal on every request.
             * If we've made it this far down this FilterChain without a redirect,
             * then there must be a session with an authentication in it.
             * Using an Acegi filter to do this would require implementing more of the Acegi framework.
             */
            public void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse, final FilterChain filterChain) throws IOException, ServletException {
                final HttpServletRequest request = (HttpServletRequest) servletRequest;
                final HttpSession session = request.getSession(false);
                final Assertion assertion = (Assertion) session.getAttribute(AbstractCasFilter.CONST_CAS_ASSERTION);

                try {
                    Cas1Authentication auth = (Cas1Authentication) assertion.getAttributes().get(AUTH_KEY);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                    filterChain.doFilter(servletRequest, servletResponse);
                } finally {
                    SecurityContextHolder.getContext().setAuthentication(null);
                }
            }
        };

        Filter jettyJsessionidRedirect = new OnlyDoFilter() {
            private final UrlPathHelper URL_PATH_HELPER = new UrlPathHelper();

            /**
             * Redirects to remove a jsessionid that a servlet container leaves in the URI if it's also in a cookie.
             * Jetty's getRequestURI() fails to remove the jsessionid (whether or not it's also in a cookie),
             * and this messes up Hudson's Stapler (as of version 1.323, at least).  CAS tickles this bug because
             * Jetty's encodeRedirectURL() is adding jsessionid on redirect after validation,
             * if it wasn't in a cookie on the request.  However, apparently Jetty also puts it in a cookie
             * on the redirect response, and Firefox accepts it.  This is a work-around to redirect that jsessionid
             * off the URL, since the cookie is enough, and the whole point of CAS redirect after validation is
             * to get a clean URL anyway (for bookmarks or restored browser tabs).
             * Other servlet containers and browser combinations may behave differently.
             * <p/>
             * This work-around does not attempt to make Hudson work in Jetty without cookies.
             * A potential approach for that would be for this filter to install an HttpServletRequestWrapper
             * that cleans jsessionid out of getRequestURI().  However, Hudson would also need to rewrite
             * all its URLs with the jsessionid, and I have no idea whether it does that.  That is an issue
             * between Hudson and Jetty, and we can just use cookies anyway.
             */
            public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
                if (request instanceof HttpServletRequest) {
                    HttpServletRequest httpRequest = (HttpServletRequest) request;
                    if (httpRequest.getRequestURI().contains(";jsessionid=") && httpRequest.isRequestedSessionIdFromCookie()) {
                        // without (i.e., with relative) protocol, host, and port
                        String decodedCleanedUrl = URL_PATH_HELPER.getRequestUri(httpRequest);
                        if (StringUtils.isNotBlank(httpRequest.getQueryString())) {
                            decodedCleanedUrl += "?"
                                    + URL_PATH_HELPER.decodeRequestString(httpRequest, httpRequest.getQueryString());
                        }
                        HttpServletResponse httpResponse = (HttpServletResponse) response;
                        httpResponse.sendRedirect(httpResponse.encodeRedirectURL(decodedCleanedUrl));
                        return;
                    }
                }
                filterChain.doFilter(request, response);
            }
        };

        // todo: Exclude paths in Hudson#getTarget() from CAS filtering/Authorization?
        // todo: Add SecurityFilters.commonProviders?
        // todo: Or, is all that just to support on-demand authentication (upgrade)?

        return new ChainedServletFilter(authenticationFilter, validationFilter, casToAcegiContext, jettyJsessionidRedirect);
    }

    private static Collection parseRolesFromValidationResponse(Script script, String response) {
        script.getBinding().setVariable("response", response);
        return (Collection) script.run();
    }

    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(); // do nothing, falling back to createFilter()
    }

//    @Override
//    public GroupDetails loadGroupByGroupname(final String groupname) throws UsernameNotFoundException, DataAccessException {
//        if(CLibrary.libc.getgrnam(groupname)==null)
//            throw new UsernameNotFoundException(groupname);
//        return new GroupDetails() {
//            @Override
//            public String getName() {
//                return groupname;
//            }
//        };
//    }

    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        private static final String CONFIRMED = "confirmed";

        public String getDisplayName() {
            return "CAS protocol version 1";
        }

        public FormValidation doCheckCasServerUrl(@QueryParameter String value) throws IOException, ServletException {
            value = Util.fixEmptyAndTrim(value);
            if (value == null) {
                return FormValidation.error("required"); // todo: doesn't Hudson have a better way?
            }
            try {
                URL url = new URL(value + "/login");
                String response = CommonUtils.getResponseFromServer(url);
                if (!response.contains("username")) {
                    return FormValidation.warning("CAS server response could not be validated.");
                }
            } catch (MalformedURLException e) {
                return FormValidation.error("Malformed CAS server URL: " + e);
            } catch (RuntimeException e) {
                return FormValidation.error("Problem getting a response from CAS server: "
                        + (e.getCause() == null ? e : e.getCause()));
            }
            return FormValidation.ok();
        }

        public FormValidation doHudsonConfirmation() { // action method stops Stapler evaluation
            return FormValidation.ok(CONFIRMED);
        }

        // This check is tedious, but it's important because the user can lock himself out.
        // This value is redundant with Hudson#getRootUrl(), but that comes from the E-mail Notification
        // section which is at the bottom of the global config page while this security is at the top,
        // and it would be a bad side-effect to try the wrong URL in the email and find yourself locked out.
        public FormValidation doCheckHudsonHostName(StaplerRequest req, StaplerResponse rsp, @QueryParameter String value) throws IOException, ServletException {
            value = Util.fixEmptyAndTrim(value);
            if (value == null) {
                return FormValidation.error("required"); // todo: does Hudson have a better way?
            }
            String testServiceUrl = CommonUtils.constructServiceUrl(req, rsp, null, value, "ticket", true); // the CAS way
            String thisDiscriptorUri = "descriptorByName/" + Cas1SecurityRealm.class.getName();
            String testMethodUri = thisDiscriptorUri + "/checkHudsonHostName";
            assert testServiceUrl.contains(testMethodUri) : testServiceUrl;
            String hudsonConfirmationUrl = testServiceUrl.substring(0, testServiceUrl.indexOf(testMethodUri));
            hudsonConfirmationUrl += thisDiscriptorUri + "/hudsonConfirmation";
            // alternative: hudsonConfirmationUrl += "securityRealms/Cas1SecurityRealm/hudsonConfirmation";
            try {
                URL url = new URL(hudsonConfirmationUrl);
                HttpSession session = req.getSession(false);
                String response;
                if (session == null) { // before security has been enabled
                    response = CommonUtils.getResponseFromServer(url);
                } else {
                    // need session for authorization (if this realm is in effect, at least)
                    response = getResponseFromServer(url, createSessionCookie(url, session));
                }
                if (!response.contains(CONFIRMED)) {
                    return FormValidation.warning("Could not validate Hudson response.");
                }
            } catch (MalformedURLException e) {
                return FormValidation.error("Malformed Hudson server URL: " + e);
            } catch (RuntimeException e) {
                Throwable specific = e.getCause() == null ? e : e.getCause();
                return FormValidation.error("Problem getting a response from Hudson server: " + specific);
            }
            return FormValidation.ok();
        }

        private static String getResponseFromServer(final URL constructedUrl, HttpCookie cookie) {
            HttpURLConnection conn = null;
            try {
                conn = (HttpURLConnection) constructedUrl.openConnection();
                // need to use cookie for session because Jetty leaves jsessionid on URI, which messes up Stapler
                conn.setRequestProperty("Cookie", cookie.toString());
                BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()));

                String line;
                StringBuffer stringBuffer = new StringBuffer();

                while ((line = in.readLine()) != null) {
                    stringBuffer.append(line);
                    stringBuffer.append("\n");
                }
                return stringBuffer.toString();
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }

        private static HttpCookie createSessionCookie(URL constructedUrl, HttpSession session) {
            HttpCookie cookie = new HttpCookie("JSESSIONID", session.getId());
            cookie.setDomain(constructedUrl.getHost());
            cookie.setPath(constructedUrl.getPath());
            return cookie;
        }

        public FormValidation doTestScript(
                @QueryParameter("rolesValidationScript") final String rolesValidationScript,
                @QueryParameter("testValidationResponse") final String testValidationResponse) {
            try {
                Script script = new GroovyShell().parse(normalizeRolesValidationScript(rolesValidationScript));
                Collection roles = parseRolesFromValidationResponse(script, testValidationResponse);
                if (roles == null) { // cast to Collection succeeds for null, so check specifically
                    return FormValidation.error("Roles Validation Script returned null.");
                }
                return FormValidation.ok("Roles parsed from the test validation response: " + roles);
            }
            catch (CompilationFailedException e) {
                return FormValidation.error("Roles Validation Script failed to compile: " + e);
            } catch (ClassCastException e) {
                return FormValidation.error("Roles Validation Script did not return a Collection: " + e);
            }
        }
    }

    @Extension
    public static DescriptorImpl install() {
        return new DescriptorImpl();
    }

    private static abstract class OnlyDoFilter implements Filter {

        public void init(FilterConfig filterConfig) throws ServletException {
            // do nothing
        }

        public void destroy() {
            // do nothing
        }
    }
}