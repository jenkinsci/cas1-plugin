package edu.hawaii.its.hudson.security;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;

import java.util.Collection;

/**
 * Adapter to Hudson uses Acegi API.
 */
public class Cas1Authentication implements Authentication {

    private final String username;
    private final GrantedAuthority[] authorities;

    public Cas1Authentication(String username, Collection roles) {
        this.username = username;
        authorities = new GrantedAuthority[roles.size()];
        int i = 0;
        for (Object role : roles) {
            authorities[i++] = new GrantedAuthorityImpl(role.toString());
        }
    }

    public GrantedAuthority[] getAuthorities() {
        return authorities;
    }

    public Object getCredentials() {
        return null; // not needed by Hudson, right?
    }

    public Object getDetails() {
        return null; // not needed by Hudson, right?
    }

    public Object getPrincipal() {
        return username;
    }

    public boolean isAuthenticated() {
        return true;
    }

    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        // do nothing
    }

    public String getName() {
        return username;
    }
}
