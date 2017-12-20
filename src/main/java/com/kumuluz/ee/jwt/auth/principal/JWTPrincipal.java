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
package com.kumuluz.ee.jwt.auth.principal;

import com.auth0.jwt.interfaces.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import java.util.*;
import java.util.logging.Logger;

/**
 * MP-JWT principal implementation.
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
public class JWTPrincipal implements JsonWebToken {

    private static final Logger LOG = Logger.getLogger(JWTPrincipal.class.getName());

    private String name;
    private String token;
    private Map<String, Claim> originalClaims;
    private Map<String, Object> convertedClaims;

    public JWTPrincipal(String name, String token, Map<String, Claim> originalClaims) {
        this.name = name;
        this.token = token;
        this.originalClaims = originalClaims;

        convertClaims();
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public Set<String> getClaimNames() {
        return convertedClaims.keySet();
    }

    @SuppressWarnings("unchecked")
    @Override
    public Set<String> getAudience() {
        String audience = (String) convertedClaims.get(Claims.aud.name());
        if (audience != null) {
            return Collections.singleton(audience);
        }

        List<String> audienceList = (List<String>) convertedClaims.get(Claims.aud.name());
        if (audienceList != null) {
            return new HashSet<>(audienceList);
        }

        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    public Set<String> getGroups() {
        List<String> groupList = (List<String>) convertedClaims.get(Claims.groups.name());

        if (groupList == null) {
            return null;
        }

        return new HashSet<>(groupList);
    }

    @SuppressWarnings("unchecked")
    @Override
    public <T> T getClaim(String claimName) {
        Claims claimType = Claims.UNKNOWN;
        T claim = null;
        try {
            claimType = Claims.valueOf(claimName);
        } catch (IllegalArgumentException e) {
            // ignore
        }

        if (claimType.equals(Claims.UNKNOWN) && !convertedClaims.containsKey(claimName)) {
            LOG.fine(String.format("No claim with name '%s' found.", claimName));
            return null;
        }

        switch (claimType) {
            case exp:
            case iat:
            case auth_time:
            case nbf:
            case updated_at:
                claim = (T) convertedClaims.get(claimType.name());
                if (claim == null) {
                    claim = (T) new Long(0);
                }
                break;
            case groups:
                claim = (T) getGroups();
                break;
            case aud:
                claim = (T) getAudience();
                break;
            case UNKNOWN:
                claim = (T) convertedClaims.get(claimName);
                break;
            default:
                claim = (T) convertedClaims.get(claimName);
        }

        return claim;
    }

    private void convertClaims() {
        convertedClaims = new HashMap<>();

        Object claimValue;
        for (Map.Entry<String, Claim> entry : originalClaims.entrySet()) {
            if ((claimValue = entry.getValue().asBoolean()) != null) {
                convertedClaims.put(entry.getKey(), claimValue);
            } else if ((claimValue = entry.getValue().asList(Object.class)) != null) {
                convertedClaims.put(entry.getKey(), claimValue);
            } else if (entry.getValue().asDouble() != null || entry.getValue().asLong() != null || entry.getValue().asInt() != null) {
                convertedClaims.put(entry.getKey(), entry.getValue().as(Number.class));
            } else if ((claimValue = entry.getValue().asMap()) != null) {
                convertedClaims.put(entry.getKey(), claimValue);
            } else if ((claimValue = entry.getValue().asString()) != null) {
                convertedClaims.put(entry.getKey(), claimValue);
            }
        }

        convertedClaims.put(Claims.raw_token.name(), token);
    }
}
