package org.miniorange.saml;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

import java.util.Arrays;

public class MoSAMLUserInfo implements UserDetails {

    private String username;
    private GrantedAuthority[] grantedAuthorities;

    public MoSAMLUserInfo (String username, GrantedAuthority[] grantedAuthorities) {
        this.username = username;
        this.grantedAuthorities = Arrays.copyOf(grantedAuthorities, grantedAuthorities.length);
    }
    @Override
    public GrantedAuthority[] getAuthorities() {
        return new GrantedAuthority[0];
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
