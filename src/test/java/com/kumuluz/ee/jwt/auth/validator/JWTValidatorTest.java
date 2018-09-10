package com.kumuluz.ee.jwt.auth.validator;

import com.kumuluz.ee.jwt.auth.cdi.JWTContextInfo;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

public class JWTValidatorTest {
    private JwksServer jwksServer;
    private JWTContextInfo jwtContextInfo;

    @AfterClass
    public void after() {
        jwksServer.stop();
    }

    @BeforeClass
    public void before() {
        try {
            jwksServer = new JwksServer(KeyTool.newKeyTool(getClass().getResource("/good_key.pem").toURI()), 8081);
            jwksServer.start();
        } catch (final Exception e) {
            throw new IllegalArgumentException(e);
        }

        jwtContextInfo = new JWTContextInfo();
        jwtContextInfo.setJwksUri("http://localhost:8081/jwks");
        jwtContextInfo.setIssuer("http://example.com");

    }

    @Test
    public void testThatTokenIsSignedByKeyInJwks() throws Exception {
        final KeyTool keyTool = KeyTool.newKeyTool(getClass().getResource("/good_key.pem").toURI());
        final String jwt = new JwtTool(keyTool, "http://example.com").generateSignedJwt();
        JWTValidator.validateToken(jwt, jwtContextInfo);
    }

    @Test(expectedExceptions = JWTValidationException.class)
    public void testThatTokenIsNotSignedByKeyInJwks() throws Exception {
        final KeyTool keyTool = KeyTool.newKeyTool(getClass().getResource("/bad_key.pem").toURI());
        final String jwt = new JwtTool(keyTool, "http://example.com").generateSignedJwt();
        JWTValidator.validateToken(jwt, jwtContextInfo);
    }
}