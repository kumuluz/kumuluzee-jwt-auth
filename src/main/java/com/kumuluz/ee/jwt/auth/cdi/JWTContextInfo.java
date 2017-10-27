package com.kumuluz.ee.jwt.auth.cdi;

import com.kumuluz.ee.configuration.cdi.ConfigBundle;
import com.kumuluz.ee.configuration.cdi.ConfigValue;
import org.bouncycastle.util.encoders.Base64;

import javax.enterprise.context.ApplicationScoped;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

@ApplicationScoped
@ConfigBundle("kumuluzee.jwt-auth")
public class JWTContextInfo {

    @ConfigValue("public-key")
    private String publicKey;
    private RSAPublicKey publicKeyDecoded;

    @ConfigValue("issuer")
    private String issuer;

    public String getPublicKey() {
        return publicKey;
    }

    public JWTContextInfo setPublicKey(String publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    public RSAPublicKey getDecodedPublicKey() {
        if (publicKeyDecoded != null) {
            return publicKeyDecoded;
        }

        try {
            byte[] publicKeyBytes = Base64.decode(publicKey);
            X509EncodedKeySpec publicKeyX509 = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKeyDecoded = (RSAPublicKey) kf.generatePublic(publicKeyX509);
        } catch (Exception e) {
            // ignore
        }

        return publicKeyDecoded;
    }

    public String getIssuer() {
        return issuer;
    }

    public JWTContextInfo setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }
}
