/**
 * 
 */
package edu.hawaii.its.hudson.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.jasig.cas.client.authentication.AuthenticationFilter;
import org.jasig.cas.client.authentication.DefaultGatewayResolverImpl;
import org.jasig.cas.client.authentication.GatewayResolver;
import org.jasig.cas.client.util.AbstractCasFilter;
import org.jasig.cas.client.util.CommonUtils;
import org.jasig.cas.client.validation.Assertion;

/**
 * @author João Antunes (joao.antunes@tagus.ist.utl.pt) - 23 de Jul de 2012
 * 
 *         Custom authentication filter that does not filter the URLs that end
 *         in /build?token=TOKEN, contrary to the {@link AuthenticationFilter}
 */
public class CustomAuthenticationFilter extends AbstractCasFilter {
    /**
     * The URL to the CAS Server login.
     */
    private String casServerLoginUrl;

    /**
     * Whether to send the renew request or not.
     */
    private boolean renew = false;

    /**
     * Whether to send the gateway request or not.
     */
    private boolean gateway = false;

    private GatewayResolver gatewayStorage = new DefaultGatewayResolverImpl();

    @Override
    protected void initInternal(final FilterConfig filterConfig) throws ServletException {
	if (!isIgnoreInitConfiguration()) {
	    super.initInternal(filterConfig);
	    setCasServerLoginUrl(getPropertyFromInitParams(filterConfig, "casServerLoginUrl", null));
	    log.trace("Loaded CasServerLoginUrl parameter: " + this.casServerLoginUrl);
	    setRenew(parseBoolean(getPropertyFromInitParams(filterConfig, "renew", "false")));
	    log.trace("Loaded renew parameter: " + this.renew);
	    setGateway(parseBoolean(getPropertyFromInitParams(filterConfig, "gateway", "false")));
	    log.trace("Loaded gateway parameter: " + this.gateway);

	    final String gatewayStorageClass = getPropertyFromInitParams(filterConfig, "gatewayStorageClass", null);

	    if (gatewayStorageClass != null) {
		try {
		    this.gatewayStorage = (GatewayResolver) Class.forName(gatewayStorageClass).newInstance();
		} catch (final Exception e) {
		    log.error(e, e);
		    throw new ServletException(e);
		}
	    }
	}
    }

    @Override
    public void init() {
	super.init();
	CommonUtils.assertNotNull(this.casServerLoginUrl, "casServerLoginUrl cannot be null.");
    }

    public static boolean isBuildRemotelyRequest(final HttpServletRequest request) {
	if (!"GET".equalsIgnoreCase(request.getMethod()))
	    return false;
	if (!StringUtils.containsIgnoreCase(request.getPathInfo(), "/build"))
	    return false;
	if (!StringUtils.containsIgnoreCase(request.getQueryString(), "token"))
	    return false;
	return true;
    }

    public final void doFilter(final ServletRequest servletRequest, final ServletResponse servletResponse,
	    final FilterChain filterChain) throws IOException, ServletException {
	final HttpServletRequest request = (HttpServletRequest) servletRequest;
	final HttpServletResponse response = (HttpServletResponse) servletResponse;
	final HttpSession session = request.getSession(false);
	final String serviceUrl = constructServiceUrl(request, response);
	final Assertion assertion = session != null ? (Assertion) session.getAttribute(CONST_CAS_ASSERTION) : null;

	if (assertion != null) {
	    filterChain.doFilter(request, response);
	    return;
	}
	
	if (isBuildRemotelyRequest(request)) {
	    filterChain.doFilter(request, response);
	    return;
	}

	final String ticket = CommonUtils.safeGetParameter(request, getArtifactParameterName());
	final boolean wasGatewayed = this.gatewayStorage.hasGatewayedAlready(request, serviceUrl);

	if (CommonUtils.isNotBlank(ticket) || wasGatewayed) {
	    filterChain.doFilter(request, response);
	    return;
	}

	final String modifiedServiceUrl;

	log.debug("no ticket, no assertion, and no 'Trigger Build remotely URL' found");
	if (this.gateway) {
	    log.debug("setting gateway attribute in session");
	    modifiedServiceUrl = this.gatewayStorage.storeGatewayInformation(request, serviceUrl);
	} else {
	    modifiedServiceUrl = serviceUrl;
	}

	if (log.isDebugEnabled()) {
	    log.debug("Constructed service url: " + modifiedServiceUrl);
	}

	final String urlToRedirectTo = CommonUtils.constructRedirectUrl(this.casServerLoginUrl, getServiceParameterName(),
		modifiedServiceUrl, this.renew, this.gateway);

	if (log.isDebugEnabled()) {
	    log.debug("redirecting to \"" + urlToRedirectTo + "\"");
	}

	response.sendRedirect(urlToRedirectTo);
    }

    public final void setRenew(final boolean renew) {
	this.renew = renew;
    }

    public final void setGateway(final boolean gateway) {
	this.gateway = gateway;
    }

    public final void setCasServerLoginUrl(final String casServerLoginUrl) {
	this.casServerLoginUrl = casServerLoginUrl;
    }

    public final void setGatewayStorage(final GatewayResolver gatewayStorage) {
	this.gatewayStorage = gatewayStorage;
    }


}
