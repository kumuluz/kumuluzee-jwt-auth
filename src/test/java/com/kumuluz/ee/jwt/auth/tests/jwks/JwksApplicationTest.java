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
package com.kumuluz.ee.jwt.auth.tests.jwks;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.RunAsClient;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.arquillian.testng.Arquillian;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * Jwks jax-rs integration tests.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
public class JwksApplicationTest extends Arquillian {

    @Deployment
    public static WebArchive createDeployment() {
        return ShrinkWrap.create(WebArchive.class)
                .addClass(JwksApplication.class)
                .addClass(JwksResource.class)
                .addAsResource("assets/jwks-config.yml", "config.yml")
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml");
    }

    @ArquillianResource
    private URL baseURL;

    private JwksServer jwksServer;

    @Test(priority = 0, groups = "jwks")
    @RunAsClient
    public void startJwksServer() {
        try {
            jwksServer = new JwksServer(new KeyTool(getClass().getResource("/good_key.pem").toURI()), 8081);
            jwksServer.start();
        } catch (final Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Test(priority = Integer.MAX_VALUE, groups = "jwks")
    @RunAsClient
    public void stopJwksServer() {
        jwksServer.stop();
    }

    @Test(groups = "jwks", priority = 1)
    @RunAsClient
    public void authTest() throws URISyntaxException {
        Response received = ClientBuilder.newClient().target(baseURL + "test")
                .request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer:" + new JwtTool(new KeyTool(
                        getClass().getResource("/good_key.pem").toURI()), "http://example.com")
                        .generateSignedJwt("tester"))
                .get();

        System.out.println(received);

        Assert.assertEquals(received.getStatus(), 200);
    }

    @Test(groups = "jwks", priority = 1)
    @RunAsClient
    public void invalidRoleTest() throws URISyntaxException {
        Response received = ClientBuilder.newClient().target(baseURL + "test/disallowed")
                .request(MediaType.APPLICATION_JSON)
                .header(HttpHeaders.AUTHORIZATION, "Bearer:" + new JwtTool(new KeyTool(
                        getClass().getResource("/good_key.pem").toURI()), "http://example.com")
                        .generateSignedJwt("tester"))
                .get();

        System.out.println(received);

        Assert.assertEquals(received.getStatus(), 403);
    }
}
