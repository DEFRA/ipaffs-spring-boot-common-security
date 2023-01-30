package uk.gov.defra.tracesx.common.security;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

@Builder
@EqualsAndHashCode
public class IdTokenUserDetails implements UserDetails {

  private final List<GrantedAuthority> authorities;
  private final String username; // upn
  private final String idToken;
  private final String displayName; // name
  private final String userObjectId; // oid
  private final String customerId; //customerId
  private final String customerOrganisationId; //customerOrganisationId
  private final String centralCompetentAuthority; //cca

  @Override
  public List<GrantedAuthority> getAuthorities() {
    return authorities;
  }

  @Override
  public String getUsername() {
    return username;
  }

  public String getIdToken() {
    return idToken;
  }

  public String getDisplayName() {
    return displayName;
  }

  public String getUserObjectId() {
    return userObjectId;
  }

  public String getCustomerId() {
    return customerId;
  }

  public String getCustomerOrganisationId() {
    return customerOrganisationId;
  }

  public String getCentralCompetentAuthority() {
    return centralCompetentAuthority;
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

  @Override
  public String getPassword() {
    return null;
  }
}
