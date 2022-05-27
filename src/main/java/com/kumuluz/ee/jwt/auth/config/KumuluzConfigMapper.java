package com.kumuluz.ee.jwt.auth.config;

import com.kumuluz.ee.configuration.ConfigurationSource;
import com.kumuluz.ee.configuration.utils.ConfigurationDispatcher;
import com.kumuluz.ee.configuration.utils.ConfigurationUtil;

import java.util.List;
import java.util.Optional;

/**
 * Configuration source that maps mp.jwt. configuration properties to kumuluzee.jwt-auth.
 *
 * @author benjamink
 * @since 1.2.0
 */
public class KumuluzConfigMapper implements ConfigurationSource {

    private static final String MP_PREFIX = "mp.jwt.";
    private static final String KUMULUZ_PREFIX = "kumuluzee.jwt-auth.";

    private ConfigurationUtil configurationUtil;

    @Override
    public void init(ConfigurationDispatcher configurationDispatcher) {
        configurationUtil = ConfigurationUtil.getInstance();
    }

    @Override
    public Optional<String> get(String key) {
        if (key.startsWith(MP_PREFIX)) {
            Optional<String> result = configurationUtil.get(KUMULUZ_PREFIX + key.substring(MP_PREFIX.length()));
            return result;
        }

        return Optional.empty();
    }

    @Override
    public Optional<Boolean> getBoolean(String key) {
        return Optional.empty();
    }

    @Override
    public Optional<Integer> getInteger(String key) {
        return Optional.empty();
    }

    @Override
    public Optional<Long> getLong(String key) {
        return Optional.empty();
    }

    @Override
    public Optional<Double> getDouble(String key) {
        return Optional.empty();
    }

    @Override
    public Optional<Float> getFloat(String key) {
        return Optional.empty();
    }

    @Override
    public Optional<Integer> getListSize(String key) {
        return Optional.empty();
    }

    @Override
    public Optional<List<String>> getMapKeys(String key) {
        return Optional.empty();
    }

    @Override
    public void watch(String key) {
    }

    @Override
    public void set(String key, String value) {
    }

    @Override
    public void set(String key, Boolean value) {
    }

    @Override
    public void set(String key, Integer value) {
    }

    @Override
    public void set(String key, Double value) {
    }

    @Override
    public void set(String key, Float value) {
    }

    /**
     * Low priority so mp.jwt still takes precedence.
     *
     * @return configuration source ordinal
     */
    @Override
    public Integer getOrdinal() {
        return 10;
    }
}
