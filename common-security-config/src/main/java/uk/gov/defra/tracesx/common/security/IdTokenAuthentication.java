package uk.gov.defra.tracesx.common.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;

public class IdTokenAuthentication extends AbstractAuthenticationToken {

  public IdTokenAuthentication(IdTokenUserDetails idTokenUserDetails) {
    super(idTokenUserDetails.getAuthorities());
    this.setAuthenticated(true);
    this.setDetails(idTokenUserDetails);
  }

  @Override
  public Object getCredentials() {
    return ((IdTokenUserDetails) getDetails()).getIdToken();
  }

  @Override
  public Object getPrincipal() {
    return ((IdTokenUserDetails) getDetails()).getUserObjectId();
  }
}
