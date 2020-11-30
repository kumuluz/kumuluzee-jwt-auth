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
package com.kumuluz.ee.jwt.auth.validator;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.kumuluz.ee.jwt.auth.cdi.JWTContextInfo;
import com.kumuluz.ee.jwt.auth.helper.ClaimHelper;
import com.kumuluz.ee.jwt.auth.principal.JWTPrincipal;
import org.eclipse.microprofile.jwt.Claims;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 * Validates the authorization token and creates a principal if authentication was successful.
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
public class JWTValidator {

    public static JWTPrincipal validateToken(String token, JWTContextInfo jwtContextInfo) throws JWTValidationException {

        DecodedJWT jwt;
        try {
            jwt = JWT.decode(token);
        } catch (JWTVerificationException e) {
            throw new JWTValidationException("Failed to validate token.", e);
        }

        Algorithm algorithm;
        RSAKeyProvider keyProvider = jwtContextInfo.getRsaKeyProvider();
        if (keyProvider != null) {
            algorithm = Algorithm.RSA256(keyProvider);
        } else if (jwtContextInfo.getJwkProvider() != null) {
            Jwk jwk;
            try {
                jwk = jwtContextInfo.getJwkProvider().get(jwt.getKeyId());
                algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            } catch (JwkException e) {
                throw new JWTValidationException("Failed to load jwks.", e);
            }
        } else {
            final RSAPublicKey decodedPublicKey = jwtContextInfo.getDecodedPublicKey();
            if (decodedPublicKey != null) {
                algorithm = Algorithm.RSA256(decodedPublicKey, null);
            } else {
                throw new IllegalStateException("Neither kumuluzee.jwt-auth.jwks-uri nor kumuluzee.jwt-auth.public-key were configured.");
            }
        }

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(jwtContextInfo.getIssuer())
                .acceptLeeway(jwtContextInfo.getMaximumLeeway())
                .build();

        try {
            verifier.verify(jwt);
        } catch (JWTVerificationException e) {
            throw new JWTValidationException("Failed to validate token.", e);
        }

        String name = ClaimHelper.getClaim(Claims.upn.name(), jwt.getClaims()).asString();
        if (name == null) {
            name = ClaimHelper.getClaim(Claims.preferred_username.name(), jwt.getClaims()).asString();
            if (name == null) {
                name = jwt.getSubject();
            }
        }

        Map<String, Claim> claims = jwt.getClaims();

        return new JWTPrincipal(name, token, claims);
    }
}
