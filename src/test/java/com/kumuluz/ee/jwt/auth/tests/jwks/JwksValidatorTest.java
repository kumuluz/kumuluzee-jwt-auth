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
package com.kumuluz.ee.jwt.auth.tests.jwks;

import com.kumuluz.ee.jwt.auth.cdi.JWTContextInfo;
import com.kumuluz.ee.jwt.auth.validator.JWTValidationException;
import com.kumuluz.ee.jwt.auth.validator.JWTValidator;
import org.testng.annotations.Test;

/**
 * Tests JWKS validator.
 *
 * @author Daniel Pfeifer
 * @since 1.1.0
 */
public class JwksValidatorTest {
    private JwksServer jwksServer;
    private JWTContextInfo jwtContextInfo;

    @Test(priority = Integer.MAX_VALUE, groups = "jwks")
    public void after() {
        jwksServer.stop();
    }

    @Test(priority = -1, groups = "jwks")
    public void before() {
        try {
            jwksServer = new JwksServer(new KeyTool(getClass().getResource("/good_key.pem").toURI()), 8081);
            jwksServer.start();
        } catch (final Exception e) {
            throw new IllegalArgumentException(e);
        }

        jwtContextInfo = new JWTContextInfo();
        jwtContextInfo.setJwksUri("http://localhost:8081/jwks");
        jwtContextInfo.setIssuer("http://example.com");
        jwtContextInfo.initJwks();
    }

    @Test(groups = "jwks")
    public void testThatTokenIsSignedByKeyInJwks() throws Exception {
        final KeyTool keyTool = new KeyTool(getClass().getResource("/good_key.pem").toURI());
        final String jwt = new JwtTool(keyTool, "http://example.com").generateSignedJwt();
        JWTValidator.validateToken(jwt, jwtContextInfo);
    }

    @Test(expectedExceptions = JWTValidationException.class, groups = "jwks")
    public void testThatTokenIsNotSignedByKeyInJwks() throws Exception {
        final KeyTool keyTool = new KeyTool(getClass().getResource("/bad_key.pem").toURI());
        final String jwt = new JwtTool(keyTool, "http://example.com").generateSignedJwt();
        JWTValidator.validateToken(jwt, jwtContextInfo);
    }
}