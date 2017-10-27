package com.kumuluz.ee.jwt.auth.context;

import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.List;
import java.util.Map;

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
//        Map<String, Object> realmAccess = principal.getClaim("realm_access");
//        if (realmAccess.containsKey("roles")) {
//            List<String> roles = (List<String>) realmAccess.get("roles");
//            return roles.contains(role);
//        }
//
//        return false;

        return principal.getGroups().contains(role);

//        return delegate.isUserInRole(role);
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
