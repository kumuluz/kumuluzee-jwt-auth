package com.kumuluz.ee.jwt.auth.feature;

import javax.annotation.Priority;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.lang.reflect.Method;

/**
 * @author Benjamin Kastelic, Sunesis ltd.
 * @since 1.0.0
 */
@Provider
public class JWTRolesAllowedDynamicFeature implements DynamicFeature {

    public void configure(ResourceInfo resourceInfo, FeatureContext configuration) {
        Method resourceMethod = resourceInfo.getResourceMethod();
        if (resourceMethod.isAnnotationPresent(DenyAll.class)) {
            configuration.register(new JWTRolesAllowedDynamicFeature.RolesAllowedRequestFilter());
        } else {
            RolesAllowed rolesAllowedAnnotation = resourceMethod.getAnnotation(RolesAllowed.class);
            if (rolesAllowedAnnotation != null) {
                configuration.register(new JWTRolesAllowedDynamicFeature.RolesAllowedRequestFilter(rolesAllowedAnnotation.value()));
            } else if (!resourceMethod.isAnnotationPresent(PermitAll.class)) {
                rolesAllowedAnnotation =  resourceInfo.getResourceClass().getAnnotation(RolesAllowed.class);

                if (rolesAllowedAnnotation != null) {
                    configuration.register(new JWTRolesAllowedDynamicFeature.RolesAllowedRequestFilter(rolesAllowedAnnotation.value()));
                }
            }
        }
    }

    @Priority(Priorities.AUTHORIZATION)
    private static class RolesAllowedRequestFilter implements ContainerRequestFilter {
        private final boolean denyAll;
        private final String[] rolesAllowed;

        RolesAllowedRequestFilter() {
            this.denyAll = true;
            this.rolesAllowed = null;
        }

        RolesAllowedRequestFilter(String[] rolesAllowed) {
            this.denyAll = false;
            this.rolesAllowed = rolesAllowed != null ? rolesAllowed : new String[0];
        }

        public void filter(ContainerRequestContext requestContext) throws IOException {
            if (!this.denyAll) {
                if (!isAuthenticated(requestContext)) {
                    requestContext.abortWith(
                            Response
                                    .status(Response.Status.UNAUTHORIZED)
                                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"MP-JWT\"")
                                    .build()
                    );
                    return;
                }

                for (String role : this.rolesAllowed) {
                    if (requestContext.getSecurityContext().isUserInRole(role)) {
                        return;
                    }
                }
            }

            requestContext.abortWith(
                    Response
                            .status(Response.Status.FORBIDDEN)
                            .build()
            );
        }

        private static boolean isAuthenticated(ContainerRequestContext requestContext) {
            return requestContext.getSecurityContext().getUserPrincipal() != null;
        }
    }
}
