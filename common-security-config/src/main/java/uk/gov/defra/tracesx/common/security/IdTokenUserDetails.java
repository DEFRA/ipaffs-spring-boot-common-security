package uk.gov.defra.tracesx.common.security;

import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.List;

@Data
@Builder
@Getter
@EqualsAndHashCode
public class IdTokenUserDetails implements UserDetails {

  private List<GrantedAuthority> authorities;
  private List<String> organisations; // b2c only
  private String username; // upn
  private String idToken;
  private String displayName; // name
  private String userObjectId; // oid
  private String contactId; //contactId

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
