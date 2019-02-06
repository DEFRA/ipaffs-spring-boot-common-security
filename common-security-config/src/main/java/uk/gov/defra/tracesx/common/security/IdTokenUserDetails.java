package uk.gov.defra.tracesx.common.security;

import java.util.List;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
@Builder
@Getter
@EqualsAndHashCode
public class IdTokenUserDetails implements UserDetails {

  private List<GrantedAuthority> authorities;
  private String username; // upn
  private String idToken;
  private String displayName; // name
  private String userObjectId; // oid

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
