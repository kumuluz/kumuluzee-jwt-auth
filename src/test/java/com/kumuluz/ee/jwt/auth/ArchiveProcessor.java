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

        war.addClass(TokenUtils.class);
        war.addClass(Claims.class);
        war.addAsResource("Token1.json");
        war.addAsResource("privateKey.pem");
        if (!war.contains("WEB-INF/classes/config.yml")) {
            war.addAsResource("assets/config.yml", "config.yml");
        }
    }
}
