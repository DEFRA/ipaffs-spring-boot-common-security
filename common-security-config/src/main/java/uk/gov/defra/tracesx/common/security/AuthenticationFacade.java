package uk.gov.defra.tracesx.common.security;

import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFacade {

  public Authentication getAuthentication() {
    return SecurityContextHolder.getContext().getAuthentication();
  }

  public void replaceAuthorities(List<GrantedAuthority> permissions) {
    IdTokenAuthentication originalAuthentication = (IdTokenAuthentication) getAuthentication();
    IdTokenUserDetails originalUserDetails = (IdTokenUserDetails) originalAuthentication.getDetails();

    IdTokenUserDetails newUserDetails = IdTokenUserDetails.builder()
        .userObjectId(originalUserDetails.getUserObjectId())
        .displayName(originalUserDetails.getDisplayName())
        .idToken(originalUserDetails.getIdToken())
        .username(originalUserDetails.getUsername())
        .authorities(permissions)
        .build();
    SecurityContextHolder.getContext().setAuthentication(
        new IdTokenAuthentication(newUserDetails));
  }
}
