package org.miniorange.saml;

import hudson.Extension;
import hudson.security.csrf.CrumbExclusion;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Extension
public class MoSAMLCrumbExclusion extends CrumbExclusion {
    @Override
    public boolean process(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String pathInfo = request.getPathInfo();
        if (ignoreCrumbCheck(pathInfo)) {
            filterChain.doFilter(request, response);
            return true;
        }
        return false;
    }

    private boolean ignoreCrumbCheck(String pathInfo) {
        if (pathInfo == null) {
            return false;
        }
        if (
                pathInfo.indexOf(MoSAMLAddIdp.MO_SAML_SP_AUTH_URL) > 0
            || pathInfo.indexOf(MoSAMLAddIdp.MO_SAML_SSO_FORCE_STOP) > 0
            || pathInfo.indexOf(MoSAMLAddIdp.MO_SAML_JENKINS_LOGIN_ACTION) > 0
        ) {
            return true;
        } else {
            return false;
        }
    }
}
