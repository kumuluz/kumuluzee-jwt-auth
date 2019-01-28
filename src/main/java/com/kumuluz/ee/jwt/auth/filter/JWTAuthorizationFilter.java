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
package com.kumuluz.ee.jwt.auth.filter;

import com.kumuluz.ee.jwt.auth.cdi.JWTContextInfo;
import com.kumuluz.ee.jwt.auth.context.JWTSecurityContext;
import com.kumuluz.ee.jwt.auth.feature.FeatureDisabledSingleton;
import com.kumuluz.ee.jwt.auth.principal.JWTPrincipal;
import com.kumuluz.ee.jwt.auth.validator.JWTValidationException;
import com.kumuluz.ee.jwt.auth.validator.JWTValidator;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;
import java.util.logging.Logger;

/**
 * MP-JWT entry point.
 * Check is authorization header is present and performs token validation and parsing.
 *
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
    public void filter(ContainerRequestContext requestContext) {

        if (!FeatureDisabledSingleton.getInstance().isEnabled()) {
            return;
        }

        String authorization = null;

        if (requestContext.getHeaders().containsKey(AUTHORIZATION_HEADER)) {
            authorization = requestContext.getHeaderString(AUTHORIZATION_HEADER);
        }

        if (authorization != null) {
            if (authorization.startsWith("Bearer")) {
                try {
                    String token = authorization.substring(7);
                    JWTPrincipal jwtPrincipal = validateToken(token, jwtContextInfo);
                    final SecurityContext securityContext = requestContext.getSecurityContext();
                    JWTSecurityContext jwtSecurityContext = new JWTSecurityContext(securityContext, jwtPrincipal);
                    requestContext.setSecurityContext(jwtSecurityContext);
                } catch (Exception e) {
                    LOG.fine("Authentication failed: " + e.getMessage());
                    requestContext.abortWith(
                            Response
                                    .status(Response.Status.UNAUTHORIZED)
                                    .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"MP-JWT\"")
                                    .build()
                    );
                }
            } else {
                LOG.fine("Authentication failed due to missing Authorization bearer token.");
                requestContext.abortWith(
                        Response
                                .status(Response.Status.UNAUTHORIZED)
                                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer realm=\"MP-JWT\"")
                                .build()
                );
            }
        }
    }

    private JWTPrincipal validateToken(String token, JWTContextInfo jwtContextInfo) throws JWTValidationException {
        return JWTValidator.validateToken(token, jwtContextInfo);
    }
}
