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

import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

/**
 * Resource used for jwks jax-rs integration testing.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
@Path("test")
@RolesAllowed({"tester", "asdasd"})
@RequestScoped
public class JwksResource {

    @Context
    private SecurityContext context;

    @GET
    @RolesAllowed("tester")
    public Response allowedRole() {

        if (!context.getUserPrincipal().getName().equals("tester")) {
            return Response.status(400).entity("User principal name is not tester.").build();
        }

        return Response.ok().build();
    }

    @GET
    @Path("/disallowed")
    @RolesAllowed("asdasd")
    public Response disallowedRole() {
        return Response.ok().build();
    }
}
