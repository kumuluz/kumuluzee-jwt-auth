package com.kumuluz.ee.jwt.auth.cdi;

import io.smallrye.jwt.auth.cdi.SmallRyeJWTAuthCDIExtension;

/**
 * @author benjamink
 * @since 1.0.0
 */
public class OptionalAwareSmallRyeJWTAuthCDIExtension extends SmallRyeJWTAuthCDIExtension {

    @Override
    protected boolean registerOptionalClaimTypeProducer() {
        return true;
    }
}
