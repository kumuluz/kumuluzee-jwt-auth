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

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import javax.json.Json;
import javax.json.JsonObject;

/**
 * Tool for signing jwt.
 *
 * @author Daniel Pfeifer
 * @since 1.1.0
 */
final class JwtTool {
    private final KeyTool keyTool;
    private final String issuer;

    JwtTool(final KeyTool keyTool, final String issuer) {
        this.keyTool = keyTool;
        this.issuer = issuer;
    }

    String generateSignedJwt() {
        return generateSignedJwt("FAKE_USER");
    }

    /**
     * Generates a base64-encoded signed JWT that expires after one hour and has the claims "sub" and
     * "preferred_username" set to the provided subject string.
     *
     * @param subject string to use for "sub" and "preferred_username".
     * @return a base64-encoded signed JWT token.
     */
    public String generateSignedJwt(final String subject) {
        final Instant now = Instant.now();
        final Instant later = now.plus(1, ChronoUnit.HOURS);
        final JsonObject joseHeader = Json.createObjectBuilder()
                .add("kid", keyTool.getJwkKeyId())
                .add("typ", "JWT")
                .add("alg", "RS256")
                .build();
        final JsonObject jwtClaims = Json.createObjectBuilder()
                .add("jti", UUID.randomUUID().toString())
                .add("sub", subject)
                .add("preferred_username", subject)
                .add("groups", Json.createArrayBuilder().add("tester"))
                .add("aud", "kumuluzee-jwt-test")
                .add("iss", issuer)
                .add("iat", now.getEpochSecond())
                .add("exp", later.getEpochSecond())
                .build();

        try {
            final byte[] joseBytes = joseHeader.toString().getBytes(StandardCharsets.UTF_8);
            final byte[] claimBytes = jwtClaims.toString().getBytes(StandardCharsets.UTF_8);

            final String joseAndClaims = Base64.getUrlEncoder().encodeToString(joseBytes) + "." +
                    Base64.getUrlEncoder().encodeToString(claimBytes);

            final Signature sha256withRSA = Signature.getInstance("SHA256withRSA");
            sha256withRSA.initSign(keyTool.getPrivateKey());
            sha256withRSA.update(joseAndClaims.getBytes(StandardCharsets.UTF_8));

            return joseAndClaims + "." + Base64.getUrlEncoder().encodeToString(sha256withRSA.sign());
        } catch (final GeneralSecurityException e) {
            throw new IllegalStateException("Could not sign JWT using SHA256withRSA.", e);
        }
    }
}