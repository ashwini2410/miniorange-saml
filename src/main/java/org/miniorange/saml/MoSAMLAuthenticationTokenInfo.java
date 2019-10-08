package org.miniorange.saml;

import org.acegisecurity.providers.AbstractAuthenticationToken;

import javax.annotation.Nonnull;

public class MoSAMLAuthenticationTokenInfo extends AbstractAuthenticationToken{

    private MoSAMLUserInfo userInfo;

    public MoSAMLAuthenticationTokenInfo(@Nonnull MoSAMLUserInfo userInfo) {
        super(userInfo.getAuthorities());
        this.userInfo = userInfo;
        this.setDetails(userInfo);
        this.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return "No Password for SAML application";
    }

    @Override
    public Object getPrincipal() {
        return userInfo;
    }
}
