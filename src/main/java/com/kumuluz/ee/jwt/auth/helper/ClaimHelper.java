package com.kumuluz.ee.jwt.auth.helper;

import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;

import java.util.Map;

public class ClaimHelper {

    public static Claim getClaim(String name, Map<String, Claim> claims) {
        if (claims.containsKey(name)) {
            return claims.get(name);
        }

        return new NullClaim();
    }
}
