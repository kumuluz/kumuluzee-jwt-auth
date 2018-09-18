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
package com.kumuluz.ee.jwt.auth;

import com.kumuluz.ee.jwt.auth.cdi.JWTContextInfo;
import com.kumuluz.ee.jwt.auth.validator.JWTValidator;
import java.util.Base64;
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
        contextInfo.setPublicKey(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
        contextInfo.init();
        return JWTValidator.validateToken(bearerToken, contextInfo);
    }
}
