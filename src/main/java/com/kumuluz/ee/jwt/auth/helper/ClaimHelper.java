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
package com.kumuluz.ee.jwt.auth.helper;

import com.auth0.jwt.impl.NullClaim;
import com.auth0.jwt.interfaces.Claim;

import javax.json.*;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Helper class for extracting claims.
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
public class ClaimHelper {

    public static Claim getClaim(String name, Map<String, Claim> claims) {
        if (claims.containsKey(name)) {
            return claims.get(name);
        }

        return new NullClaim();
    }

    public static JsonValue convertBoolean(Boolean bool) {
        return bool ? JsonValue.TRUE : JsonValue.FALSE;
    }

    public static JsonString convertString(String str) {
        return (JsonString) wrapValue(str);
    }

    public static JsonNumber convertNumber(Number number) {
        return (JsonNumber) wrapValue(number);
    }

    public static JsonArray convertCollection(Collection list) {
        return (JsonArray) wrapValue(list);
    }

    @SuppressWarnings("unchecked")
    public static JsonObject convertMap(Map<String, Object> map) {
        JsonObjectBuilder builder = Json.createObjectBuilder();

        if (map == null) {
            return builder.build();
        }

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

    public static JsonValue wrapValue(Object value) {
        JsonValue jsonValue = null;
        if (value instanceof String) {
            String str = (String) value;
            jsonValue = Json.createObjectBuilder()
                    .add("tmp", str)
                    .build()
                    .getJsonString("tmp");
        }
        else if (value instanceof Number) {
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
        else if(value instanceof Collection) {
            JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
            Collection collection = (Collection) value;
            for(Object element : collection) {
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
}
