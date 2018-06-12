package com.kumuluz.ee.jwt.auth;

import org.jboss.arquillian.container.test.impl.enricher.resource.URLResourceProvider;
import org.jboss.arquillian.container.test.spi.client.deployment.ApplicationArchiveProcessor;
import org.jboss.arquillian.container.test.spi.client.deployment.AuxiliaryArchiveAppender;
import org.jboss.arquillian.core.spi.LoadableExtension;
import org.jboss.arquillian.test.spi.enricher.resource.ResourceProvider;

/**
 * Registers Arquillian extensions.
 *
 * @author Urban Malc
 * @since 1.1.0
 */
public class JwtAuthArquillianExtension implements LoadableExtension {

    @Override
    public void register(ExtensionBuilder extensionBuilder) {
        extensionBuilder.service(ApplicationArchiveProcessor.class, ArchiveProcessor.class);
        extensionBuilder.service(AuxiliaryArchiveAppender.class, JwtAuthLibraryAppender.class);

        extensionBuilder.override(ResourceProvider.class,
                URLResourceProvider.class, com.kumuluz.ee.jwt.auth.URLResourceProvider.class);
    }
}
