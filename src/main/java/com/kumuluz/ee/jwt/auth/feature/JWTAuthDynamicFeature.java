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

import io.smallrye.jwt.auth.jaxrs.JWTAuthenticationFilter;
import io.smallrye.jwt.auth.jaxrs.JWTAuthorizationFilterRegistrar;
import io.smallrye.jwt.auth.jaxrs.SmallRyeJWTAuthJaxRsFeature;

import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Feature;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

/**
 * A JAX-RS feature that configures and registers the {@link SmallRyeJWTAuthJaxRsFeature}, which performs the
 * role based authorization.
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
@Provider
public class JWTAuthDynamicFeature implements Feature {

    @Override
    public boolean configure(FeatureContext featureContext) {
        if (!FeatureDisabledSingleton.getInstance().isEnabled()) {
            return false;
        }

        featureContext.register(JWTAuthorizationFilterRegistrar.class);

        return true;
    }
}
