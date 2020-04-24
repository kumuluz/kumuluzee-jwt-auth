package com.kumuluz.ee.jwt.auth.processor;

import org.eclipse.microprofile.auth.LoginConfig;

import javax.annotation.processing.AbstractProcessor;
import javax.annotation.processing.Filer;
import javax.annotation.processing.ProcessingEnvironment;
import javax.annotation.processing.RoundEnvironment;
import javax.lang.model.SourceVersion;
import javax.lang.model.element.Element;
import javax.lang.model.element.ElementKind;
import javax.lang.model.element.TypeElement;
import javax.lang.model.type.TypeMirror;
import javax.tools.FileObject;
import javax.tools.StandardLocation;
import javax.ws.rs.core.Application;
import java.io.*;
import java.nio.file.NoSuchFileException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Compile-time annotation processor for LoginConfig. Generates a service file.
 *
 * @author Benjamin Kastelic
 */
public class AnnotationProcessor extends AbstractProcessor {

    private static final Logger LOG = Logger.getLogger(AnnotationProcessor.class.getName());

    private static final String MP_JWT_AUTH_METHOD = "MP-JWT";

    private Filer filer;

    @Override
    public SourceVersion getSupportedSourceVersion() {
        return SourceVersion.latest();
    }

    @Override
    public Set<String> getSupportedAnnotationTypes() {
        return Collections.singleton("*");
    }

    @Override
    public synchronized void init(ProcessingEnvironment processingEnv) {
        super.init(processingEnv);
        filer = processingEnv.getFiler();
    }

    @Override
    public boolean process(Set<? extends TypeElement> annotations, RoundEnvironment roundEnvironment) {
        Set<? extends Element> elements;

        // classes with @LoginConfig(authMethod = "MP-JWT") annotation
        Set<String> mpJwtApplicationElementNames = new HashSet<>();

        elements = roundEnvironment.getElementsAnnotatedWith(LoginConfig.class);

        elements.stream()
                .filter(this::extendsJAXRSApplicationClass)
                .filter(this::isMpJwtAuthEnabled)
                .forEach(element -> extractElementName(mpJwtApplicationElementNames, element));

        try {
            if (!mpJwtApplicationElementNames.isEmpty()) {
                writeFile(mpJwtApplicationElementNames, "META-INF/services/javax.ws.rs.core.Application");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false;
    }

    private boolean extendsJAXRSApplicationClass(Element element) {
        TypeMirror applicationClass = processingEnv.getElementUtils().getTypeElement(Application.class.getCanonicalName()).asType();
        return processingEnv.getTypeUtils().isAssignable(element.asType(), applicationClass);
    }

    private boolean isMpJwtAuthEnabled(Element element) {
        LoginConfig loginConfig = element.getAnnotation(LoginConfig.class);
        return loginConfig != null && loginConfig.authMethod().equals(MP_JWT_AUTH_METHOD);
    }

    private void extractElementName(Set<String> elementNames, Element element) {
        ElementKind elementKind = element.getKind();

        if (elementKind.equals(ElementKind.CLASS)) {
            elementNames.add(element.toString());
        }
    }

    private void writeFile(Set<String> content, String resourceName) throws IOException {
        FileObject file = readOldFile(content, resourceName);
        if (file != null) {
            try {
                writeFile(content, resourceName, file);
                return;
            } catch (IllegalStateException e) {
                e.printStackTrace();
            }
        }
        writeFile(content, resourceName, null);
    }

    private void writeFile(Set<String> content, String resourceName, FileObject overrideFile) throws IOException {
        FileObject file = overrideFile;
        if (file == null) {
            file = filer.createResource(StandardLocation.CLASS_OUTPUT, "", resourceName);
        }
        try (Writer writer = file.openWriter()) {
            for (String serviceClassName : content) {
                writer.write(serviceClassName);
                writer.write(System.lineSeparator());
            }
        }
    }

    private FileObject readOldFile(Set<String> content, String resourceName) throws IOException {
        Reader reader = null;
        try {
            final FileObject resource = filer.getResource(StandardLocation.CLASS_OUTPUT, "", resourceName);
            reader = resource.openReader(true);
            readOldFile(content, reader);
            return resource;
        } catch (NoSuchFileException | FileNotFoundException e) {
            // close reader, return null
        } finally {
            if (reader != null) {
                reader.close();
            }
        }
        return null;
    }

    private static void readOldFile(Set<String> content, Reader reader) throws IOException {
        try (BufferedReader bufferedReader = new BufferedReader(reader)) {
            String line = bufferedReader.readLine();
            while (line != null) {
                content.add(line);
                line = bufferedReader.readLine();
            }
        }
    }
}
