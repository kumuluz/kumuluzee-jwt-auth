# KumuluzEE JWT Authentication
[![Build Status](https://img.shields.io/travis/kumuluz/kumuluzee-metrics/master.svg?style=flat)](https://travis-ci.org/kumuluz/kumuluzee-jwt-auth)

> KumuluzEE JWT Authentication extension provides Microprofile compliant role based access control microservice endpoints using OpenID Connect and JSON Web Tokens.

KumuluzEE JWT Authentication implements the [MicroProfile JWT Authentication 1.0 API](https://microprofile.io/project/eclipse/microprofile-jwt-auth).

## Usage

You can enable KumuluzEE JWT Authentication support by adding the following dependency:

```xml
<dependency>
    <groupId>com.kumuluz.ee.jwt</groupId>
    <artifactId>kumuluzee-jwt-auth</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

The provided filters should be added automatically upon running. If that doesn't happen or if you wish to manually 
include the provided filters, register the following classes:

- JWTAuthorizationFilter
- JWTRolesAllowedDynamicFeature  

## Configuration

In order for the extension to work correctly you must provide two configuration properties:

```yaml
kumuluzee:
  jwt-auth:
    public-key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnOTgnGBISzm3pKuG8QXMVm6eEuTZx8Wqc8D9gy7vArzyE5QC/bVJNFwlz...
    issuer: http://example.org/auth
``` 

The `public key` and `issuer` configuration properties are used to validate and decode the received `Authorization` 
token.

##  Accessing token information

There are multiple ways with which you can access the decoded token data. The standard way is to access the principal 
contained in the security context:

```java
import org.eclipse.microprofile.jwt.JsonWebToken;
import javax.ws.rs.core.SecurityContext;

@Context
private SecurityContext sc;

...

JsonWebToken principal = securityContext.getUserPrincipal();

...
```  

You can also get the information using CDI and injection:

```java
import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import java.util.Optional;
import javax.json.*;

// Principal
@Inject
private JsonWebToken principal;

// Raw types
@Inject
@Claim(standard = Claims.raw_token)
private String rawToken;
@Inject (1)
@Claim(standard=Claims.iat)
private Long issuedAt;

// ClaimValue wrappers
@Inject (2)
@Claim(standard = Claims.raw_token)
private ClaimValue<String> rawTokenCV;
@Inject
@Claim(standard = Claims.iss)
private ClaimValue<String> issuer;
@Inject
@Claim(standard = Claims.jti)
private ClaimValue<String> jti;
@Inject (3)
@Claim("jti")
private ClaimValue<Optional<String>> optJTI;
@Inject
@Claim("jti")
private ClaimValue objJTI;
@Inject
@Claim("groups")
private ClaimValue<Set<String>> groups;
@Inject (4)
@Claim(standard=Claims.iat)
private ClaimValue<Long> issuedAtCV;
@Inject
@Claim("iat")
private ClaimValue<Long> dupIssuedAt;
@Inject
@Claim("sub")
private ClaimValue<Optional<String>> optSubject;
@Inject
@Claim("auth_time")
private ClaimValue<Optional<Long>> authTime;
@Inject (5)
@Claim("custom-missing")
private ClaimValue<Optional<Long>> custom;

//
@Inject
@Claim(standard = Claims.jti)
private Instance<String> providerJTI;
@Inject (6)
@Claim(standard = Claims.iat)
private Instance<Long> providerIAT;
@Inject
@Claim("groups")
private Instance<Set<String>> providerGroups;

//
@Inject
@Claim(standard = Claims.jti)
private JsonString jsonJTI;
@Inject
@Claim(standard = Claims.iat)
private JsonNumber jsonIAT;
@Inject (7)
@Claim("roles")
private JsonArray jsonRoles;
@Inject
@Claim("customObject")
private JsonObject jsonCustomObject;
```

## Changelog

Recent changes can be viewed on Github on the [Releases Page](https://github.com/kumuluz/kumuluzee-jwt-auth/releases)

## Contribute

See the [contributing docs](https://github.com/kumuluz/kumuluzee-jwt-auth/blob/master/CONTRIBUTING.md)

When submitting an issue, please follow the 
[guidelines](https://github.com/kumuluz/kumuluzee-jwt-auth/blob/master/CONTRIBUTING.md#bugs).

When submitting a bugfix, write a test that exposes the bug and fails before applying your fix. Submit the test 
alongside the fix.

When submitting a new feature, add tests that cover the feature.

## License

MIT
