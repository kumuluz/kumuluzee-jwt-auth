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
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
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

    private RSAPublicKey publicKeyDecoded;

    private String jwksUri;
    private JwksRSAKeyProvider jwkProvider;

    private String issuer;

    @PostConstruct
    public void init() {
        ConfigurationUtil config = ConfigurationUtil.getInstance();
        String publicKey;
        publicKey = config.get("mp.jwt.verify.publickey")
                .orElse(config.get("kumuluzee.jwt-auth.public-key").orElse(null));

        if (publicKey == null) {
            String location = config.get("mp.jwt.verify.publickey.location").orElse(null);

            if (location != null) {
                URL url;

                try {
                    url = new URL(location);
                } catch (MalformedURLException e) {
                    url = getClass().getClassLoader().getResource(location.substring(1));
                }

                if (url != null) {
                    try {
                        publicKey = new BufferedReader(new InputStreamReader(url.openStream())).lines()
                                .collect(Collectors.joining("\n"));
                    } catch (IOException e) {
                        LOG.log(Level.SEVERE, "Could not resolve public key from " + url.toExternalForm(), e);
                    }
                }
            }
        }
        publicKeyDecoded = decodeJWK(publicKey);

        if (publicKey != null && publicKeyDecoded == null) {
            // remove header and footer
            publicKey = publicKey.replaceAll("-+BEGIN PUBLIC KEY-+", "");
            publicKey = publicKey.replaceAll("-+END PUBLIC KEY-+", "");
            // remove all non base64 characters
            publicKey = publicKey.replaceAll("[^A-Za-z0-9+/=]", "");

            publicKeyDecoded = decodeJWK(new String(Base64.getDecoder().decode(publicKey)));
        }

        if (publicKey != null && publicKeyDecoded == null) {
            try {
                byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
                X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKeyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                publicKeyDecoded = (RSAPublicKey) kf.generatePublic(publicKeyX509);
            } catch (Exception e) {
                // ignore
            }
        }

        jwksUri = config.get("kumuluzee.jwt-auth.jwks-uri").orElse(null);

        issuer = config.get("mp.jwt.verify.issuer")
                .orElse(config.get("kumuluzee.jwt-auth.issuer").orElse(null));

        initJwks();
    }

    public void initJwks() {
        if (jwksUri != null) {
            try {
                jwkProvider = new JwksRSAKeyProvider(new URL(jwksUri));
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

    public RSAKeyProvider getJwkProvider() {
        return jwkProvider;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    @SuppressWarnings("unchecked")
    private RSAPublicKey decodeJWK(String jwk) {
        try {
            Map<String, Object> vals = new ObjectMapper().readValue(jwk, new TypeReference<Map<String, Object>>() {
            });
            if (vals.containsKey("keys") && vals.get("keys") instanceof List &&
                    ((List) vals.get("keys")).get(0) instanceof Map) {
                vals = (Map<String, Object>) ((List) vals.get("keys")).get(0);
            }
            if (vals.containsKey("n") && vals.containsKey("e") &&
                    vals.get("n") instanceof String && vals.get("e") instanceof String) {
                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(((String) vals.get("n"))));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(((String) vals.get("e"))));

                return (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(new RSAPublicKeySpec(modulus, exponent));
            }
        } catch (Exception ignored) {
        }

        return null;
    }
}
