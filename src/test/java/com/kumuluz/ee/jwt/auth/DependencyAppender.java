package com.kumuluz.ee.jwt.auth;

import com.kumuluz.ee.testing.arquillian.spi.MavenDependencyAppender;

import java.util.ArrayList;
import java.util.List;
import java.util.ResourceBundle;

/**
 * Adds the required dependencies to the deployments.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
public class DependencyAppender implements MavenDependencyAppender {

    private static final ResourceBundle versionsBundle = ResourceBundle.getBundle("META-INF/kumuluzee/versions");

    private static final String JERSEY_MEDIA_JSON_PROCESSING_VERSION = "2.27";
    private static final String NIMBUS_JOSE_JWT_VERSION = "4.23";

    @Override
    public List<String> addLibraries() {

        List<String> libs = new ArrayList<>();

        libs.add("com.kumuluz.ee:kumuluzee-jax-rs-jersey:");
        libs.add("com.kumuluz.ee:kumuluzee-json-p-jsonp:");
        libs.add("com.kumuluz.ee:kumuluzee-cdi-weld:");
        libs.add("org.eclipse.microprofile.jwt:microprofile-jwt-auth-api:" +
                versionsBundle.getString("microprofile-jwt-auth-version"));
        libs.add("com.auth0:java-jwt:" +
                versionsBundle.getString("java-jwt-version"));

        libs.add("com.nimbusds:nimbus-jose-jwt:" + NIMBUS_JOSE_JWT_VERSION);
        libs.add("org.glassfish.jersey.media:jersey-media-json-processing:" + JERSEY_MEDIA_JSON_PROCESSING_VERSION);

        return libs;
    }
}
