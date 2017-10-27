package com.kumuluz.ee.jwt.auth.filter;

import com.kumuluz.ee.jwt.auth.cdi.JWTContextInfo;
import com.kumuluz.ee.jwt.auth.context.JWTSecurityContext;
import com.kumuluz.ee.jwt.auth.principal.JWTPrincipal;
import com.kumuluz.ee.jwt.auth.validator.JWTValidator;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
@ApplicationScoped
@Provider
@Priority(Priorities.AUTHENTICATION)
@PreMatching
public class JWTAuthorizationFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(JWTAuthorizationFilter.class.getName());

    private static final String AUTHORIZATION_HEADER = "Authorization";

    @Inject
    private JWTContextInfo jwtContextInfo;

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        String authorization = null;

        if (requestContext.getHeaders().containsKey(AUTHORIZATION_HEADER)) {
            authorization = requestContext.getHeaderString(AUTHORIZATION_HEADER);
        }

        if (authorization != null && authorization.startsWith("Bearer")) {
            try {
                String token = authorization.substring(7);
                JWTPrincipal jwtPrincipal = validateToken(token, jwtContextInfo);
                final SecurityContext securityContext = requestContext.getSecurityContext();
                JWTSecurityContext jwtSecurityContext = new JWTSecurityContext(securityContext, jwtPrincipal);
                requestContext.setSecurityContext(jwtSecurityContext);
            } catch (Exception e) {
                LOG.fine("Authentication failed: " + e.getMessage());
                requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
            }
        } else {
            LOG.fine("Authentication failed due to missing Authorization bearer token.");
            requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED).build());
        }
    }

    private JWTPrincipal validateToken(String token, JWTContextInfo jwtContextInfo) {
        return JWTValidator.validateToken(token, jwtContextInfo);
    }
}
