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

import com.kumuluz.ee.configuration.cdi.ConfigBundle;
import com.kumuluz.ee.configuration.cdi.ConfigValue;
import org.bouncycastle.util.encoders.Base64;

import javax.enterprise.context.ApplicationScoped;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;

/**
 * MP-JWT configuration settings
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
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

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
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

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }
}
