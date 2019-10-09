package org.miniorange.saml;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.pac4j.core.io.WritableResource;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Logger;

public class MoSAMLIdpMetadataResource implements WritableResource {
    private static final Logger LOGGER = Logger.getLogger(MoSAMLIdpMetadataResource.class.getName());

    private String fileName;

    public MoSAMLIdpMetadataResource(String fileName) {
        //LOGGER.fine("MoSAMLIdpMetadataResource constructor is called");
        if (StringUtils.isNotEmpty(fileName)) {
            this.fileName = fileName;
        }
    }

    @Override
    public OutputStream getOutputStream() throws IOException {
        return FileUtils.openOutputStream(getFile());
    }

    @Override
    public boolean exists() {
        return getFile().exists();
    }

    @Override
    public String getFilename() {
        return fileName;
    }

    @Override
    public InputStream getInputStream() throws IOException {
        return FileUtils.openInputStream(getFile());
    }

    @Override
    public File getFile() {
        return new File(fileName);
    }
}
