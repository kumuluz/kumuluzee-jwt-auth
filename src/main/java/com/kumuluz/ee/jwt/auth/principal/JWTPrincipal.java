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

import javax.json.*;
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

        return new HashSet<>();
    }

    @SuppressWarnings("unchecked")
    @Override
    public Set<String> getGroups() {
        List<String> groupList = (List<String>) convertedClaims.get(Claims.groups.name());

        return groupList != null
                ? new HashSet<>(groupList)
                : new HashSet<>();
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
            } else if ((claimValue = entry.getValue().asLong()) != null) {
                convertedClaims.put(entry.getKey(), claimValue);
            } else if ((claimValue = entry.getValue().asMap()) != null) {
                convertedClaims.put(entry.getKey(), claimValue);
            } else if ((claimValue = entry.getValue().asString()) != null) {
                convertedClaims.put(entry.getKey(), claimValue);
            }
        }

        Set<String> customClaimNames = getCustomClaimNames(convertedClaims.keySet());
        for(String claimName : customClaimNames) {
            Object claim = convertedClaims.get(claimName);
            if(claim instanceof List) {
                convertList(claimName);
            } else if(claim instanceof Map) {
                convertMap(claimName);
            } else if(claim instanceof Number) {
                convertNumber(claimName);
            }
        }

        convertedClaims.put(Claims.raw_token.name(), token);
    }

    private void convertList(String claimName) {
        List list = (List) convertedClaims.get(claimName);
        JsonArray jsonArray = (JsonArray) wrapValue(list);
        convertedClaims.put(claimName, jsonArray);
    }

    @SuppressWarnings("unchecked")
    private void convertMap(String claimName) {
        Map map = (Map) convertedClaims.get(claimName);
        JsonObject jsonObject = convertMap(map);
        convertedClaims.put(claimName, jsonObject);
    }

    private void convertNumber(String claimName) {
        Number number = (Number) convertedClaims.get(claimName);
        JsonNumber jsonNumber = (JsonNumber) wrapValue(number);
        convertedClaims.put(claimName, jsonNumber);
    }

    @SuppressWarnings("unchecked")
    private JsonObject convertMap(Map<String, Object> map) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        for(Map.Entry<String,Object> entry : map.entrySet()) {
            Object entryValue = entry.getValue();
            if(entryValue instanceof Map) {
                JsonObject entryJsonObject = convertMap((Map<String, Object>) entryValue);
                builder.add(entry.getKey(), entryJsonObject);
            } else if(entryValue instanceof List) {
                JsonArray array = (JsonArray) wrapValue(entryValue);
                builder.add(entry.getKey(), array);
            } else if(entryValue instanceof Long || entryValue instanceof Integer) {
                long lvalue = ((Number) entryValue).longValue();
                builder.add(entry.getKey(), lvalue);
            } else if(entryValue instanceof Double || entryValue instanceof Float) {
                double dvalue = ((Number) entryValue).doubleValue();
                builder.add(entry.getKey(), dvalue);
            } else if(entryValue instanceof Boolean) {
                boolean flag = (Boolean) entryValue;
                builder.add(entry.getKey(), flag);
            } else if(entryValue instanceof String) {
                builder.add(entry.getKey(), entryValue.toString());
            }
        }
        return builder.build();
    }

    private JsonValue wrapValue(Object value) {
        JsonValue jsonValue = null;
        if(value instanceof Number) {
            Number number = (Number) value;
            if((number instanceof Long) || (number instanceof Integer)) {
                jsonValue = Json.createObjectBuilder()
                        .add("tmp", number.longValue())
                        .build()
                        .getJsonNumber("tmp");
            } else {
                jsonValue = Json.createObjectBuilder()
                        .add("tmp", number.doubleValue())
                        .build()
                        .getJsonNumber("tmp");
            }
        }
        else if(value instanceof Boolean) {
            Boolean flag = (Boolean) value;
            jsonValue = flag ? JsonValue.TRUE : JsonValue.FALSE;
        }
        else if(value instanceof List) {
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            List list = (List) value;
            for(Object element : list) {
                if(element instanceof String) {
                    arrayBuilder.add(element.toString());
                }
                else {
                    JsonValue jvalue = wrapValue(element);
                    arrayBuilder.add(jvalue);
                }
            }
            jsonValue = arrayBuilder.build();
        }
        return jsonValue;
    }

    private Set<String> getCustomClaimNames(Collection<String> claimNames) {
        HashSet<String> customNames = new HashSet<>(claimNames);
        for(Claims claim : Claims.values()) {
            customNames.remove(claim.name());
        }
        return customNames;
    }
}
