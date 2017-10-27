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
