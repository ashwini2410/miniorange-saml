package org.miniorange.saml;

import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.captcha.CaptchaSupport;
import org.acegisecurity.AuthenticationException;

import java.io.IOException;
import java.io.OutputStream;

public class MoHudsonPrivateSecurityRealm  extends HudsonPrivateSecurityRealm {
    MoHudsonPrivateSecurityRealm() {
        super(false, false, new CaptchaSupport() {
            @Override
            public boolean validateCaptcha(String id, String text) {
                return false;
            }

            @Override
            public void generateImage(String id, OutputStream ios) throws IOException {

            }
        });
    }

    @Override
    protected Details authenticate(String username, String password) throws AuthenticationException {
        return super.authenticate(username, password);
    }
}
