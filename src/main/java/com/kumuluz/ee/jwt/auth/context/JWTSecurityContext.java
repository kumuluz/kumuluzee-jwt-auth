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
package com.kumuluz.ee.jwt.auth.context;

import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

/**
 * MP-JWT security context implementation
 *
 * @author Benjamin Kastelic
 * @since 1.0.0
 */
public class JWTSecurityContext implements SecurityContext {

    private SecurityContext delegate;
    private JsonWebToken principal;

    public JWTSecurityContext(SecurityContext delegate, JsonWebToken principal) {
        this.delegate = delegate;
        this.principal = principal;
    }

    @Override
    public Principal getUserPrincipal() {
        return principal;
    }

    @SuppressWarnings("unchecked")
    @Override
    public boolean isUserInRole(String role) {

        return principal.getGroups().contains(role);
    }

    @Override
    public boolean isSecure() {
        return delegate.isSecure();
    }

    @Override
    public String getAuthenticationScheme() {
        return delegate.getAuthenticationScheme();
    }
}
