package com.kumuluz.ee.jwt.auth.util;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Initialized;
import javax.enterprise.event.Observes;
import javax.ws.rs.core.Application;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.logging.Logger;

/**
 * Interceptor class for LoginConfig annotation.
 */
@ApplicationScoped
public class AnnotationProcessorUtil {

    private static final Logger LOG = Logger.getLogger(AnnotationProcessorUtil.class.getName());

    private boolean mpJwtEnabled;

    public void init(@Observes @Initialized(ApplicationScoped.class) Object context) {
        List<Application> applications = new ArrayList<>();
        ServiceLoader.load(Application.class).forEach(applications::add);

        if (applications.size() > 0) {
            mpJwtEnabled = true;
        }
    }

    public boolean isMpJwtEnabled() {
        return mpJwtEnabled;
    }
}
