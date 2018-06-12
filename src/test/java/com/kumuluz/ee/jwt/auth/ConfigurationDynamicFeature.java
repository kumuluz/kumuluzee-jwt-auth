package com.kumuluz.ee.jwt.auth;

import com.kumuluz.ee.jwt.auth.filter.JWTAuthorizationFilter;

import javax.inject.Inject;
import javax.ws.rs.container.DynamicFeature;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.FeatureContext;
import javax.ws.rs.ext.Provider;

/**
 * Provides the {@link JWTAuthorizationFilter} to the deployment.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
@Provider
public class ConfigurationDynamicFeature implements DynamicFeature {

    @Inject
    private JWTAuthorizationFilter jwtAuthorizationFilter;

    @Override
    public void configure(ResourceInfo resourceInfo, FeatureContext featureContext) {
        featureContext.register(jwtAuthorizationFilter);
    }
}
