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
