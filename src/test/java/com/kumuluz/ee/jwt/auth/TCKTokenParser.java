package com.kumuluz.ee.jwt.auth;

import com.kumuluz.ee.jwt.auth.cdi.JWTContextInfo;
import com.kumuluz.ee.jwt.auth.validator.JWTValidator;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.jwt.tck.util.ITokenParser;

import java.security.PublicKey;

/**
 * Implementation of {@link ITokenParser}, required by the TCK.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
public class TCKTokenParser implements ITokenParser {

    @Override
    public JsonWebToken parse(String bearerToken, String issuer, PublicKey publicKey) throws Exception {
        JWTContextInfo contextInfo = new JWTContextInfo();
        contextInfo.setIssuer(issuer);
        contextInfo.setPublicKey(Base64.toBase64String(publicKey.getEncoded()));
        return JWTValidator.validateToken(bearerToken, contextInfo);
    }
}
