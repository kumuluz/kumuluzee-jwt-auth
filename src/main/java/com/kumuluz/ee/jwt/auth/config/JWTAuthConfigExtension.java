package com.kumuluz.ee.jwt.auth.config;

import com.kumuluz.ee.common.ConfigExtension;
import com.kumuluz.ee.common.config.EeConfig;
import com.kumuluz.ee.common.dependencies.EeExtensionDef;
import com.kumuluz.ee.common.dependencies.EeExtensionGroup;
import com.kumuluz.ee.common.wrapper.KumuluzServerWrapper;
import com.kumuluz.ee.configuration.ConfigurationSource;

import java.util.Collections;
import java.util.List;

/**
 * @author benjamink
 * @since 1.0.0
 */
@EeExtensionDef(name = "JWTAuthMp", group = EeExtensionGroup.CONFIG)
public class JWTAuthConfigExtension implements ConfigExtension {

    @Override
    public void load() {
    }

    @Override
    public void init(KumuluzServerWrapper server, EeConfig eeConfig) {
    }

    @Override
    public ConfigurationSource getConfigurationSource() {
        return null;
    }

    @Override
    public List<ConfigurationSource> getConfigurationSources() {
        return Collections.singletonList(new KumuluzConfigMapper());
    }
}
