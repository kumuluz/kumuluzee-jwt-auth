# KumuluzEE JWT Authentication
[![Build Status](https://img.shields.io/travis/kumuluz/kumuluzee-metrics/master.svg?style=flat)](https://travis-ci.org/kumuluz/kumuluzee-jwt-auth)

> KumuluzEE JWT Authentication extension provides Microprofile compliant role based access control microservice endpoints using OpenID Connect and JSON Web Tokens.

KumuluzEE JWT Authentication implements the [MicroProfile JWT Authentication 1.1 API](https://microprofile.io/project/eclipse/microprofile-jwt-auth).

## Usage

You can enable KumuluzEE JWT Authentication support by adding the following dependency:

```xml
<dependency>
    <groupId>com.kumuluz.ee.jwt</groupId>
    <artifactId>kumuluzee-jwt-auth</artifactId>
    <version>${kumuluzee-jwt-auth.version}</version>
</dependency>
```

The `LoginConfig` annotation should be added to the JAX-RS Application:

```java
@LoginConfig(authMethod = "MP-JWT")
@ApplicationPath("v1")
public class CustomerApplication extends Application {
}
```

## Configuration

Given you work with a static public key for verification you must provide two configuration properties:

```yaml
kumuluzee:
  jwt-auth:
    public-key: MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnOTgnGBISzm3pKuG8QXMVm6eEuTZx8Wqc8D9gy7vArzyE5QC/bVJNFwlz...
    issuer: http://example.org/auth
``` 

The supplied public key can be in any of the following formats:

- PKCS#8 PEM
- JWK
- JWKS
- Base64 URL encoded JWK
- Base64 URL encoded JWKS

If, on the other hand, you use JWKS as a source for your verification keys then you instead provide following two
configuration properties:

```yaml
kumuluzee:
  jwt-auth:
    jwks-uri: https://example.com/jwks.json
    issuer: http://example.org/auth
``` 

The `public-key`/`jwks-uri` and `issuer` configuration properties are used to validate and decode the received
`Authorization` token.

If both `public-key` and `jwks-uri` are set, the `jwks-uri` takes precedence and the `public-key` is ignored.

JWT authentication can be disabled by setting the `kumuluzee.jwt-auth.enabled` configuration property to `false`.

You can configure the maximum leeway the authenticator allows for timestamp claims (such as _nbf_ or _iat_) by
setting `kumuluzee.jwt-auth.maximum-leeway`. The default value is `60`, meaning sixty seconds.

##  Accessing token information

There are multiple ways with which you can access the decoded token data. The standard way is to access the principal 
contained in the security context:

```java
import org.eclipse.microprofile.jwt.JsonWebToken;
import javax.ws.rs.core.SecurityContext;

@Context
private SecurityContext sc;

...

JsonWebToken principal = sc.getUserPrincipal();

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

