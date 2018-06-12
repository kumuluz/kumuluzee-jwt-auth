package com.kumuluz.ee.jwt.auth;

import org.jboss.arquillian.container.test.impl.enricher.resource.OperatesOnDeploymentAwareProvider;
import org.jboss.arquillian.test.api.ArquillianResource;

import java.lang.annotation.Annotation;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * Provides the server URL to the TCK tests.
 * Overrides {@link org.jboss.arquillian.container.test.impl.enricher.resource.URLResourceProvider}.
 * <p>
 * Original provider provides URLs with trailing slash, while TCKs expect an URL without trailing slash
 * (see: <a href=https://github.com/eclipse/microprofile-jwt-auth/issues/71>
 * https://github.com/eclipse/microprofile-jwt-auth/issues/71</a>).
 * <p>
 * Should be removed when fix in TCKs is released.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
public class URLResourceProvider extends OperatesOnDeploymentAwareProvider {

    @Override
    public Object doLookup(ArquillianResource resource, Annotation... qualifiers) {
        try {
            return new URL("http://localhost:8080");
        } catch (MalformedURLException e) {
            throw new IllegalStateException("Error converting to URL", e);
        }
    }

    @Override
    public boolean canProvide(Class<?> type) {
        return type.isAssignableFrom(URL.class);
    }
}
