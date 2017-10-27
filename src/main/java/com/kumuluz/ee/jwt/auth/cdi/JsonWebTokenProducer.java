package com.kumuluz.ee.jwt.auth.cdi;

import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.enterprise.context.RequestScoped;
import javax.enterprise.inject.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;

@RequestScoped
public class JsonWebTokenProducer {

    @Context
    private SecurityContext securityContext;

    @Produces
    public JsonWebToken getJWTPrincipal() {
        return (JsonWebToken) securityContext.getUserPrincipal();
    }
}
