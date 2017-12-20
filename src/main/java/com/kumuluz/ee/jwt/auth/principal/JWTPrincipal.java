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
import com.kumuluz.ee.jwt.auth.helper.ClaimHelper;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonNumber;
import javax.json.JsonString;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;

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
    private Map<String, Object> jsonClaims;

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
        return jsonClaims.keySet();
    }

    @Override
    public String getSubject() {
        JsonString subject = (JsonString) jsonClaims.get(Claims.sub.name());
        if (subject == null) {
            return null;
        }

        return subject.getString();
    }

    @Override
    public String getTokenID() {
        JsonString tokenId = (JsonString) jsonClaims.get(Claims.jti.name());
        if (tokenId == null) {
            return null;
        }

        return tokenId.getString();
    }

    @Override
    public String getIssuer() {
        JsonString issuer = (JsonString) jsonClaims.get(Claims.iss.name());
        if (issuer == null) {
            return null;
        }

        return issuer.getString();
    }

    @SuppressWarnings("unchecked")
    @Override
    public Set<String> getAudience() {
        JsonString audience = (JsonString) jsonClaims.get(Claims.aud.name());
        if (audience != null) {
            return Collections.singleton(audience.getString());
        }

        JsonArray audienceArray = (JsonArray) jsonClaims.get(Claims.aud.name());
        if (audienceArray != null) {
            return audienceArray.getValuesAs(JsonString.class).stream().map(JsonString::getString).collect(Collectors.toSet());
        }

        return null;
    }

    private JsonArray getAudienceAsJsonArray() {
        JsonString audience = (JsonString) jsonClaims.get(Claims.aud.name());
        if (audience != null) {
            return Json.createArrayBuilder()
                    .add(audience.getString())
                    .build();
        }

        return (JsonArray) jsonClaims.get(Claims.aud.name());
    }

    @Override
    public long getExpirationTime() {
        JsonNumber expirationType = (JsonNumber) jsonClaims.get(Claims.exp.name());

        if (expirationType == null) {
            return 0;
        }

        return expirationType.longValue();
    }

    @Override
    public long getIssuedAtTime() {
        JsonNumber issuedAtTime = (JsonNumber) jsonClaims.get(Claims.iat.name());

        if (issuedAtTime == null) {
            return 0;
        }

        return issuedAtTime.longValue();
    }

    @Override
    public String getRawToken() {
        JsonString rawToken = (JsonString) jsonClaims.get(Claims.raw_token.name());
        if (rawToken == null) {
            return null;
        }

        return rawToken.getString();
    }

    @SuppressWarnings("unchecked")
    @Override
    public Set<String> getGroups() {
        JsonArray groupList = (JsonArray) jsonClaims.get(Claims.groups.name());

        if (groupList == null) {
            return null;
        }

        return groupList.getValuesAs(JsonString.class).stream().map(JsonString::getString).collect(Collectors.toSet());
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

        if (claimType.equals(Claims.UNKNOWN) && !jsonClaims.containsKey(claimName)) {
            LOG.fine(String.format("No claim with name '%s' found.", claimName));
            return null;
        }

        switch (claimType) {
            case sub:
                return (T) getSubject();
            case exp:
                return (T) (Long) getExpirationTime();
            case iat:
                return (T) (Long) getIssuedAtTime();
            case jti:
                return (T) getTokenID();
            case iss:
                return (T) getIssuer();
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
            default:
                claim = (T) jsonClaims.get(claimName);
                if (claim instanceof JsonString) {
                    claim = (T) ((JsonString) claim).getString();
                }
        }

        return claim;
    }

    public <T> T getClaimForInjection(String claimName) {
        Claims claimType = Claims.UNKNOWN;
        T claim = null;
        try {
            claimType = Claims.valueOf(claimName);
        } catch (IllegalArgumentException e) {
            // ignore
        }

        if (claimType.equals(Claims.UNKNOWN) && !jsonClaims.containsKey(claimName)) {
            LOG.fine(String.format("No claim with name '%s' found.", claimName));
            return null;
        }

        switch (claimType) {
            case aud:
                claim = (T) getAudienceAsJsonArray();
                break;
            case UNKNOWN:
            default:
                claim = (T) jsonClaims.get(claimName);
        }

        return claim;
    }

    private void convertClaims() {
        convertedClaims = new HashMap<>();
        jsonClaims = new HashMap<>();

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

        for(String claimName : originalClaims.keySet()) {
            Object claim = convertedClaims.get(claimName);
            if (claim instanceof String) {
                String str = (String) claim;
                jsonClaims.put(claimName, ClaimHelper.convertString(str));
            } else if (claim instanceof Boolean) {
                Boolean bool = (Boolean) claim;
                jsonClaims.put(claimName, ClaimHelper.convertBoolean(bool));
            } else if(claim instanceof List) {
                Collection collection = (Collection) claim;
                jsonClaims.put(claimName, ClaimHelper.convertCollection(collection));
            } else if(claim instanceof Map) {
                Map map = (Map) claim;
                jsonClaims.put(claimName, ClaimHelper.convertMap(map));
            } else if(claim instanceof Number) {
                Number number = (Number) claim;
                jsonClaims.put(claimName, ClaimHelper.convertNumber(number));
            }
        }

        jsonClaims.put(Claims.raw_token.name(), ClaimHelper.convertString(token));
    }
}
