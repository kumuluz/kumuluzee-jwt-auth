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

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.kumuluz.ee.jwt.auth.cdi.JWTContextInfo;
import com.kumuluz.ee.jwt.auth.helper.ClaimHelper;
import com.kumuluz.ee.jwt.auth.principal.JWTPrincipal;
import org.eclipse.microprofile.jwt.Claims;

import java.util.Map;

public class JWTValidator {

    public static JWTPrincipal validateToken(String token, JWTContextInfo jwtContextInfo) {
        Algorithm algorithm = Algorithm.RSA256(jwtContextInfo.getDecodedPublicKey(), null);
        JWTVerifier verifier = JWT.require(algorithm).withIssuer(jwtContextInfo.getIssuer()).build();
        DecodedJWT jwt = verifier.verify(token);

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
