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

import com.kumuluz.ee.jwt.auth.cdi.ClaimProducer;
import com.kumuluz.ee.jwt.auth.context.JWTSecurityContext;
import com.kumuluz.ee.jwt.auth.feature.JWTRolesAllowedDynamicFeature;
import com.kumuluz.ee.jwt.auth.filter.JWTAuthorizationFilter;
import com.kumuluz.ee.jwt.auth.helper.ClaimHelper;
import com.kumuluz.ee.jwt.auth.principal.JWTPrincipal;
import com.kumuluz.ee.jwt.auth.validator.JWTValidator;
import org.jboss.arquillian.container.test.spi.client.deployment.CachedAuxilliaryArchiveAppender;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;

/**
 * Builds JWT Auth JAR and adds it to the deployments.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
public class JwtAuthLibraryAppender extends CachedAuxilliaryArchiveAppender {

    @Override
    protected Archive<?> buildArchive() {

        return ShrinkWrap.create(JavaArchive.class, "kumuluzee-jwt-auth-0.0.0.jar")
                .addPackages(true, JWTValidator.class.getPackage())
                .addPackages(true, JWTPrincipal.class.getPackage())
                .addPackages(true, ClaimHelper.class.getPackage())
                .addPackages(true, JWTAuthorizationFilter.class.getPackage())
                .addPackages(true, JWTRolesAllowedDynamicFeature.class.getPackage())
                .addPackages(true, JWTSecurityContext.class.getPackage())
                .addPackages(true, ClaimProducer.class.getPackage())
                .addClass(JWTAuthExtension.class)
                .addAsServiceProvider(com.kumuluz.ee.common.Extension.class, JWTAuthExtension.class)
                .addAsResource("META-INF/beans.xml");
    }
}
