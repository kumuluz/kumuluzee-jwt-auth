package com.kumuluz.ee.jwt.auth;

import com.kumuluz.ee.jwt.auth.feature.JWTRolesAllowedDynamicFeature;
import com.kumuluz.ee.jwt.auth.filter.JWTAuthorizationFilter;
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

        return ShrinkWrap.create(JavaArchive.class, "kumuluzee-jwt-auth.jar")
                .addPackages(true, JWTAuthExtension.class.getPackage())
                .deleteClasses(JWTAuthorizationFilter.class, JWTRolesAllowedDynamicFeature.class)
                .addAsServiceProvider(com.kumuluz.ee.common.Extension.class, JWTAuthExtension.class)
                .addAsResource("META-INF/beans.xml");
    }
}
