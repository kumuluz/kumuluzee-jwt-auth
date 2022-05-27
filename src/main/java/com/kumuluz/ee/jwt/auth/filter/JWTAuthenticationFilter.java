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

import com.kumuluz.ee.configuration.utils.ConfigurationUtil;
import com.kumuluz.ee.jwt.auth.feature.FeatureDisabledSingleton;

import javax.annotation.Priority;
import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.PreMatching;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.Optional;

/**
 * MP-JWT entry point.
 * Checks if authorization header is present and performs token validation and parsing.
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
@ApplicationScoped
@Provider
@Priority(Priorities.AUTHENTICATION)
@PreMatching
public class JWTAuthenticationFilter extends io.smallrye.jwt.auth.jaxrs.JWTAuthenticationFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) throws IOException {
        if (!FeatureDisabledSingleton.getInstance().isEnabled()) {
            return;
        }

        try {
            super.filter(requestContext);
        } catch (NotAuthorizedException e) {
            throw new NotAuthorizedException(e, "Bearer");
        }
    }
}
