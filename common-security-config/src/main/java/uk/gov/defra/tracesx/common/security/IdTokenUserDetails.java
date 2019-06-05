package uk.gov.defra.tracesx.common.security;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

@Builder
@EqualsAndHashCode
public class IdTokenUserDetails implements UserDetails {

  private List<GrantedAuthority> authorities;
  private String username; // upn
  private String idToken;
  private String displayName; // name
  private String userObjectId; // oid
  private String customerId; //customerId
  private String customerOrganisationId; //customerOrganisationId

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
