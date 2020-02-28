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
package com.kumuluz.ee.jwt.auth.cdi;

import com.kumuluz.ee.jwt.auth.principal.JWTPrincipal;
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Dependent;
import javax.enterprise.context.SessionScoped;
import javax.enterprise.inject.Produces;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.DeploymentException;
import javax.enterprise.inject.spi.InjectionPoint;
import javax.inject.Inject;
import javax.json.*;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Claims producer.
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
@Dependent
public class ClaimProducer {

    @Inject
    private JsonWebToken callerPrincipal;

    // region Basic types - String, Set<String>, Long, Boolean
    @Produces
    @Claim
    public String getClaimAsString(InjectionPoint injectionPoint) {
        JsonString claim = getClaim(injectionPoint);
        if (claim == null) {
            return null;
        }

        return claim.getString();
    }

    @Produces
    @Claim
    public Set<String> getClaimAsStringSet(InjectionPoint injectionPoint) {
        JsonArray claim = getClaim(injectionPoint);
        if (claim == null) {
            return null;
        }

        return claim.getValuesAs(JsonString.class)
                .stream()
                .map(JsonString::getString)
                .collect(Collectors.toSet());
    }

    @Produces
    @Claim
    public Long getClaimAsLong(InjectionPoint injectionPoint) {
        JsonNumber claim = getClaim(injectionPoint);
        if (claim == null) {
            return null;
        }

        return claim.longValue();
    }

    @Produces
    @Claim
    public Boolean getClaimAsBoolean(InjectionPoint injectionPoint) {
        JsonValue claim = getClaim(injectionPoint);
        if (claim == null) {
            return null;
        }

        if (claim.getValueType().equals(JsonValue.ValueType.TRUE)) {
            return Boolean.TRUE;
        } else if (claim.getValueType().equals(JsonValue.ValueType.FALSE)) {
            return Boolean.FALSE;
        }

        return null;
    }
    // endregion

    // region Json types - JsonString, JsonArray, JsonNumber, JsonObject
    @Produces
    @Claim
    public JsonString getClaimAsJsonString(InjectionPoint injectionPoint) {
        return getClaim(injectionPoint);
    }

    @Produces
    @Claim
    public JsonArray getClaimAsJsonArray(InjectionPoint injectionPoint) {
        return getClaim(injectionPoint);
    }

    @Produces
    @Claim
    public JsonNumber getClaimAsJsonNumber(InjectionPoint injectionPoint) {
        return getClaim(injectionPoint);
    }

    @Produces
    @Claim
    public JsonObject getClaimAsJsonObject(InjectionPoint injectionPoint) {
        return getClaim(injectionPoint);
    }
    // endregion

    // region Optional basic types - Optional<String>, Optional<Set<String>>, Optional<Long>, Optional<Boolean>
    @Produces
    @Claim
    public Optional<String> getClaimAsOptionalString(InjectionPoint injectionPoint) {
        String claim = getClaimAsString(injectionPoint);
        return Optional.ofNullable(claim);
    }

    @Produces
    @Claim
    public Optional<Set<String>> getClaimAsOptionalStringSet(InjectionPoint injectionPoint) {
        Set<String> claim = getClaimAsStringSet(injectionPoint);
        return Optional.ofNullable(claim);
    }

    @Produces
    @Claim
    public Optional<Long> getClaimAsOptionalLong(InjectionPoint injectionPoint) {
        Long claim = getClaimAsLong(injectionPoint);
        return Optional.ofNullable(claim);
    }

    @Produces
    @Claim
    public Optional<Boolean> getClaimAsOptionalBoolean(InjectionPoint injectionPoint) {
        Boolean claim = getClaimAsBoolean(injectionPoint);
        return Optional.ofNullable(claim);
    }
    // endregion

    // region Optional Json types - Optional<JsonString>, Optional<JsonArray>, Optional<JsonNumber>, Optional<JsonObject>
    @Produces
    @Claim
    public Optional<JsonString> getClaimAsOptionalJsonString(InjectionPoint injectionPoint) {
        JsonString claim = getClaimAsJsonString(injectionPoint);
        return Optional.ofNullable(claim);
    }

    @Produces
    @Claim
    public Optional<JsonArray> getClaimAsOptionalJsonArray(InjectionPoint injectionPoint) {
        JsonArray claim = getClaimAsJsonArray(injectionPoint);
        return Optional.ofNullable(claim);
    }

    @Produces
    @Claim
    public Optional<JsonNumber> getClaimAsOptionalJsonNumber(InjectionPoint injectionPoint) {
        JsonNumber claim = getClaimAsJsonNumber(injectionPoint);
        return Optional.ofNullable(claim);
    }

    @Produces
    @Claim
    public Optional<JsonObject> getClaimAsOptionalJsonObject(InjectionPoint injectionPoint) {
        JsonObject claim = getClaimAsJsonObject(injectionPoint);
        return Optional.ofNullable(claim);
    }
    // endregion

    // region ClaimValue basic types - ClaimValue<String>, ClaimValue<Set<String>>, ClaimValue<Long>, ClaimValue<Boolean>
    @Produces
    @Claim
    public ClaimValue<String> getClaimAsClaimValueString(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        String claim = getClaimAsString(injectionPoint);

        return new ClaimValue<String>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public String getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Set<String>> getClaimAsClaimValueStringSet(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Set<String> claim = getClaimAsStringSet(injectionPoint);

        return new ClaimValue<Set<String>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Set<String> getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Long> getClaimAsClaimValueLong(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Long claim = getClaimAsLong(injectionPoint);

        return new ClaimValue<Long>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Long getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Boolean> getClaimAsClaimValueBoolean(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Boolean claim = getClaimAsBoolean(injectionPoint);

        return new ClaimValue<Boolean>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Boolean getValue() {
                return claim;
            }
        };
    }
    // endregion

    // region ClaimValue Json types - ClaimValue<JsonString>, ClaimValue<JsonArray>, ClaimValue<JsonNumber>, ClaimValue<JsonObject>
    @Produces
    @Claim
    public ClaimValue<JsonString> getClaimAsClaimValueJsonString(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        JsonString claim = getClaimAsJsonString(injectionPoint);

        return new ClaimValue<JsonString>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public JsonString getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<JsonArray> getClaimAsClaimValueJsonArray(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        JsonArray claim = getClaimAsJsonArray(injectionPoint);

        return new ClaimValue<JsonArray>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public JsonArray getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<JsonNumber> getClaimAsClaimValueJsonNumber(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        JsonNumber claim = getClaimAsJsonNumber(injectionPoint);

        return new ClaimValue<JsonNumber>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public JsonNumber getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<JsonObject> getClaimAsClaimValueJsonObject(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        JsonObject claim = getClaimAsJsonObject(injectionPoint);

        return new ClaimValue<JsonObject>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public JsonObject getValue() {
                return claim;
            }
        };
    }
    // endregion

    // region ClaimValue optional basic types - ClaimValue<Optional<String>>, ClaimValue<Optional<Set<String>>>, ClaimValue<Optional<Long>>, ClaimValue<Optional<Boolean>>
    @Produces
    @Claim
    public ClaimValue<Optional<String>> getClaimAsClaimValueOptionalString(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Optional<String> claim = getClaimAsOptionalString(injectionPoint);

        return new ClaimValue<Optional<String>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Optional<String> getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Optional<Set<String>>> getClaimAsClaimValueOptionalStringSet(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Optional<Set<String>> claim = getClaimAsOptionalStringSet(injectionPoint);

        return new ClaimValue<Optional<Set<String>>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Optional<Set<String>> getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Optional<Long>> getClaimAsClaimValueOptionalLong(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Optional<Long> claim = getClaimAsOptionalLong(injectionPoint);

        return new ClaimValue<Optional<Long>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Optional<Long> getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Optional<Boolean>> getClaimAsClaimValueOptionalBoolean(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Optional<Boolean> claim = getClaimAsOptionalBoolean(injectionPoint);

        return new ClaimValue<Optional<Boolean>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Optional<Boolean> getValue() {
                return claim;
            }
        };
    }
    // endregion

    // region ClaimValue optional Json types - ClaimValue<Optional<JsonString>>, ClaimValue<Optional<JsonArray>>, ClaimValue<Optional<JsonNumber>>, ClaimValue<Optional<JsonValue>>
    @Produces
    @Claim
    public ClaimValue<Optional<JsonString>> getClaimAsClaimValueOptionalJsonString(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Optional<JsonString> claim = getClaimAsOptionalJsonString(injectionPoint);

        return new ClaimValue<Optional<JsonString>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Optional<JsonString> getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Optional<JsonArray>> getClaimAsClaimValueOptionalJsonArray(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Optional<JsonArray> claim = getClaimAsOptionalJsonArray(injectionPoint);

        return new ClaimValue<Optional<JsonArray>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Optional<JsonArray> getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Optional<JsonNumber>> getClaimAsClaimValueOptionalJsonNumber(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Optional<JsonNumber> claim = getClaimAsOptionalJsonNumber(injectionPoint);

        return new ClaimValue<Optional<JsonNumber>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Optional<JsonNumber> getValue() {
                return claim;
            }
        };
    }

    @Produces
    @Claim
    public ClaimValue<Optional<JsonObject>> getClaimAsClaimValueOptionalJsonObject(InjectionPoint injectionPoint) {
        String claimName = getClaimName(injectionPoint);
        Optional<JsonObject> claim = getClaimAsOptionalJsonObject(injectionPoint);

        return new ClaimValue<Optional<JsonObject>>() {
            @Override
            public String getName() {
                return claimName;
            }

            @Override
            public Optional<JsonObject> getValue() {
                return claim;
            }
        };
    }
    // endregion

    private <T> T getClaim(InjectionPoint injectionPoint) {
        validateClaim(injectionPoint);
        String claimName = getClaimName(injectionPoint);
        return callerPrincipal != null
                ? ((JWTPrincipal) callerPrincipal).getClaimForInjection(claimName)
                : null;
    }

    private void validateClaim(InjectionPoint injectionPoint) {
        Class beanClass;
        Bean bean = injectionPoint.getBean();
        if (bean == null) {
            beanClass = injectionPoint.getMember().getDeclaringClass();
        } else {
            beanClass = bean.getBeanClass();
        }

        if (beanClass.getAnnotation(ApplicationScoped.class) != null || beanClass.getAnnotation(SessionScoped.class) != null) {
            throw new DeploymentException("@Claim injection is not supported in @ApplicationScoped and @SessionScoped contexts.");
        }

        Claim claimAnnotation = injectionPoint.getAnnotated().getAnnotation(Claim.class);

        String claimValue = claimAnnotation.value();
        Claims claimStandard = claimAnnotation.standard();

        if (claimValue.isEmpty() && claimStandard.equals(Claims.UNKNOWN)) {
            throw new DeploymentException("At least one parameter must be specified.");
        }

        if (!claimValue.isEmpty() && !claimStandard.equals(Claims.UNKNOWN)) {
            throw new DeploymentException("Ambiguous use of @Claim qualifier; only one of the parameters is allowed at any one time.");
        }
    }

    private String getClaimName(InjectionPoint injectionPoint) {
        Claim claimAnnotation = injectionPoint.getAnnotated().getAnnotation(Claim.class);

        String claimValue = claimAnnotation.value();
        Claims claimStandard = claimAnnotation.standard();

        String claimName = claimValue;
        if (claimName.isEmpty()) {
            claimName = claimStandard.name();
        }

        return claimName;
    }
}
