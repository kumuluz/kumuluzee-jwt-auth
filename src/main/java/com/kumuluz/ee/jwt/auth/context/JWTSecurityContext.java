package com.kumuluz.ee.jwt.auth.context;

import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

public class JWTSecurityContext implements SecurityContext {

    private SecurityContext delegate;
    private JsonWebToken principal;

    public JWTSecurityContext(SecurityContext delegate, JsonWebToken principal) {
        this.delegate = delegate;
        this.principal = principal;
    }

    @Override
    public Principal getUserPrincipal() {
        return principal;
    }

    @SuppressWarnings("unchecked")
    @Override
    public boolean isUserInRole(String role) {

        return principal.getGroups().contains(role);
    }

    @Override
    public boolean isSecure() {
        return delegate.isSecure();
    }

    @Override
    public String getAuthenticationScheme() {
        return delegate.getAuthenticationScheme();
    }
}
