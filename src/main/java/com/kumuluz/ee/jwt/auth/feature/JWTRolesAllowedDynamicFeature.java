/*
 *  Copyright (c) 2014-2017 Kumuluz and/or its affiliates
 *  and other contributors as indicated by the @author tags and
 *  the contributor list.
 *
 *  Licensed under the MIT License (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  https://opensource.org/licenses/MIT
 *
 *  The software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND, express or
 *  implied, including but not limited to the warranties of merchantability,
 *  fitness for a particular purpose and noninfringement. in no event shall the
 *  authors or copyright holders be liable for any claim, damages or other
 *  liability, whether in an action of contract, tort or otherwise, arising from,
 *  out of or in connection with the software or the use or other dealings in the
 *  software. See the License for the specific language governing permissions and
 *  limitations under the License.
 */
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
 * A JAX-RS dynamic feature that configures and registers the {@link RolesAllowedRequestFilter}, which performs the
 * role based authorization.
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
@Provider
public class JWTRolesAllowedDynamicFeature implements DynamicFeature {

    public void configure(ResourceInfo resourceInfo, FeatureContext configuration) {
        if (!FeatureDisabledSingleton.getInstance().isEnabled()) {
            return;
        }

        final Method resourceMethod = resourceInfo.getResourceMethod();

        if (resourceMethod.isAnnotationPresent(DenyAll.class)) {
            configuration.register(new JWTRolesAllowedDynamicFeature.RolesAllowedRequestFilter());
            return;
        }

        RolesAllowed rolesAllowedAnnotation = resourceMethod.getAnnotation(RolesAllowed.class);
        if (rolesAllowedAnnotation != null) {
            configuration.register(new JWTRolesAllowedDynamicFeature.RolesAllowedRequestFilter(rolesAllowedAnnotation.value()));
            return;
        }

        if (resourceMethod.isAnnotationPresent(PermitAll.class)) {
            return;
        }

        final Class<?> resourceClass = resourceInfo.getResourceClass();

        if (resourceClass.isAnnotationPresent(DenyAll.class)) {
            configuration.register(new JWTRolesAllowedDynamicFeature.RolesAllowedRequestFilter());
            return;
        }

        RolesAllowed classRolesAllowedAnnotation =  resourceClass.getAnnotation(RolesAllowed.class);
        if (classRolesAllowedAnnotation != null) {
            configuration.register(new JWTRolesAllowedDynamicFeature.RolesAllowedRequestFilter(classRolesAllowedAnnotation.value()));
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
                if (rolesAllowed.length > 0 && !isAuthenticated(requestContext)) {
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
