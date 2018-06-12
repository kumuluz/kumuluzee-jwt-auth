package com.kumuluz.ee.jwt.auth;

import com.kumuluz.ee.jwt.auth.feature.JWTRolesAllowedDynamicFeature;
import com.kumuluz.ee.jwt.auth.filter.JWTAuthorizationFilter;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.tck.util.TokenUtils;
import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.test.spi.TestClass;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.spec.WebArchive;

/**
 * Auguments the archive with additional assets.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
public class ArchiveProcessor implements ApplicationArchiveProcessor {

    @Override
    public void process(Archive<?> archive, TestClass testClass) {

        WebArchive war = archive.as(WebArchive.class);

        war.addClass(JWTAuthorizationFilter.class);
        war.addClass(JWTRolesAllowedDynamicFeature.class);
        war.addClass(TokenUtils.class);
        war.addClass(Claims.class);
        war.addAsResource("Token1.json");
        war.addAsResource("privateKey.pem");
        war.addAsResource("assets/config.yml", "config.yml");
    }
}
