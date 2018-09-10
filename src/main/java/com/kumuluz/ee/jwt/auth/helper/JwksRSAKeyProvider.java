package com.kumuluz.ee.jwt.auth.helper;

import com.auth0.jwk.JwkException;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import java.net.URL;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class JwksRSAKeyProvider implements RSAKeyProvider {
    private final JwkProvider jwkProvider;

    private JwksRSAKeyProvider(JwkProvider jwkProvider) {
        this.jwkProvider = jwkProvider;
    }

    public static JwksRSAKeyProvider newJwksRSAKeyProvider(URL jwksUri) {
        final JwkProvider jwkProvider = new JwkProviderBuilder(jwksUri).build();
        return new JwksRSAKeyProvider(jwkProvider);
    }

    @Override
    public RSAPublicKey getPublicKeyById(String keyId) {
        try {
            final PublicKey publicKey = jwkProvider.get(keyId).getPublicKey();
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException(String.format("Key with ID '%s' was found in JWKS but is not a RSA-key.", keyId));
            }
            return (RSAPublicKey) publicKey;
        } catch (JwkException e) {
            throw new IllegalArgumentException(String.format("Key with ID '%s' was couldn't be fetched from JWKS.", keyId), e);
        }
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return null;
    }

    @Override
    public String getPrivateKeyId() {
        return null;
    }
}
