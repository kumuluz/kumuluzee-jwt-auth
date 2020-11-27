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

import com.auth0.jwk.*;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kumuluz.ee.configuration.utils.ConfigurationUtil;
import com.kumuluz.ee.jwt.auth.helper.JwksRSAKeyProvider;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

/**
 * MP-JWT configuration settings
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
@ApplicationScoped
public class JWTContextInfo {

    private static final Logger LOG = Logger.getLogger(JWTContextInfo.class.getName());

    private static final String DEFAULT_JWKS_PATH = "/.well-known/jwks.json";
    private static final String MP_CONFIG_PUBLIC_KEY = "mp.jwt.verify.publickey";
    private static final String KUMULUZ_CONFIG_PUBLIC_KEY = "kumuluzee.jwt-auth.public-key";

    private static final String DEFAULT_LEEWAY_SECONDS = "60";

    private RSAPublicKey publicKeyDecoded;

    private String jwksUri;
    private JwkProvider jwkProvider;
    private RSAKeyProvider rsaKeyProvider;

    private String issuer;

    private int maximumLeeway;

    @PostConstruct
    public void init() {
        ConfigurationUtil config = ConfigurationUtil.getInstance();

        issuer = config.get("mp.jwt.verify.issuer").orElse(config.get("kumuluzee.jwt-auth.issuer").orElse(null));
        maximumLeeway = Integer.parseInt(config.get("kumuluzee.jwt-auth.maximum-leeway").orElse(DEFAULT_LEEWAY_SECONDS));

        final List<String> publickeyChildKeys = config.getMapKeys(MP_CONFIG_PUBLIC_KEY).orElse(null);
        String keyLocation = publickeyChildKeys != null && publickeyChildKeys.contains("location") ? config.get(MP_CONFIG_PUBLIC_KEY + ".location").orElse(null) : null;
        String publicKeyPayload = config.get(MP_CONFIG_PUBLIC_KEY).orElse(config.get(KUMULUZ_CONFIG_PUBLIC_KEY).orElse(null));

        //jwks url
        if (keyLocation != null && keyLocation.endsWith(DEFAULT_JWKS_PATH)) {
            jwkProvider = new UrlJwkProvider(keyLocation.replace(DEFAULT_JWKS_PATH, ""));
            LOG.fine(() -> "Loaded JWKS key from " + keyLocation);
            return;
        }

        //public key url
        if (keyLocation != null) {
            URL url;
            try {
                url = new URL(keyLocation);
            } catch (MalformedURLException e) {
                url = getClass().getClassLoader().getResource(keyLocation.substring(1));
            }

            if (url != null) {
                try (BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(url.openStream()))) {
                    publicKeyPayload = bufferedReader.lines()
                            .collect(Collectors.joining("\n"));
                } catch (IOException e) {
                    LOG.log(Level.SEVERE, "Could not resolve public key from " + url.toExternalForm(), e);
                }
            }
        }

        if (publicKeyPayload != null) {
            //config key payload
            try {
                jwkProvider = new KumuluzJwkProvider(publicKeyPayload);
                return;
            } catch (SigningKeyNotFoundException e) {
            }

            try {
                // remove header and footer
                publicKeyPayload = publicKeyPayload.replaceAll("-+BEGIN PUBLIC KEY-+", "").replaceAll("-+END PUBLIC KEY-+", "");
                // remove all non base64 characters
                publicKeyPayload = publicKeyPayload.replaceAll("[^A-Za-z0-9+/=]", "");

                byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPayload);
                X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                publicKeyDecoded = (RSAPublicKey) kf.generatePublic(publicKeyX509);
            } catch (Exception e) {
                // ignore
            }
        } else {
            LOG.fine(() -> "No public keys payload provided");
        }

        jwksUri = config.get("kumuluzee.jwt-auth.jwks-uri").orElse(null);
        initJwks();
    }

    public void initJwks() {
        if (jwksUri != null) {
            try {
                rsaKeyProvider = new JwksRSAKeyProvider(new URL(jwksUri));
            } catch (MalformedURLException e) {
                throw new IllegalArgumentException("The provided kumuluzee.jwt-auth.jwks-uri is not a valid URL.", e);
            }
        }
    }

    public RSAPublicKey getDecodedPublicKey() {
        return publicKeyDecoded;
    }

    public String getJwksUri() {
        return jwksUri;
    }

    public void setJwksUri(String jwksUri) {
        this.jwksUri = jwksUri;
    }

    public JwkProvider getJwkProvider() {
        return jwkProvider;
    }

    public RSAKeyProvider getRsaKeyProvider() {
        return rsaKeyProvider;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public int getMaximumLeeway() {
        return maximumLeeway;
    }

    public void setMaximumLeeway(int maximumLeeway) {
        this.maximumLeeway = maximumLeeway;
    }

    protected static class KumuluzJwkProvider implements JwkProvider {

        private Map<String, Jwk> jwkMap;

        @SuppressWarnings("unchecked")
        public KumuluzJwkProvider(String jwkPayload) throws SigningKeyNotFoundException {

            try {
                Map<String, Object> jwks = new ObjectMapper().readValue(jwkPayload, new TypeReference<Map<String, Object>>() {
                });

                this.jwkMap = new HashMap<>();

                List<Map<String, Object>> keys = (List) jwks.get("keys");
                if (keys != null && !keys.isEmpty()) {
                    try {
                        Iterator var3 = keys.iterator();

                        while (var3.hasNext()) {
                            Map<String, Object> values = (Map) var3.next();
                            Jwk jwk = Jwk.fromValues(values);
                            jwkMap.put(jwk.getId(), jwk);
                        }
                    } catch (IllegalArgumentException var5) {
                        throw new SigningKeyNotFoundException("Failed to parse jwk from json", var5);
                    }
                } else {
                    throw new SigningKeyNotFoundException("No keys found in payload", null);
                }

            } catch (Exception e) {
                throw new SigningKeyNotFoundException("No keys found in payload", e);
            }
        }

        @Override
        public Jwk get(String keyId) throws JwkException {

            if (jwkMap.containsKey(keyId)) {
                return jwkMap.get(keyId);
            }

            throw new SigningKeyNotFoundException("No key found in Kumuluz JWK provider with kid " + keyId, null);
        }
    }

}
