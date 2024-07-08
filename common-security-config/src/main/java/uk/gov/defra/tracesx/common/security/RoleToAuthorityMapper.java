package uk.gov.defra.tracesx.common.security;

import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class RoleToAuthorityMapper {

  public List<GrantedAuthority> mapRoles(List<String> roles) {
    return roles.stream().map(this::mapRole).toList();
  }

  private GrantedAuthority mapRole(String role) {
    return OrganisationGrantedAuthority.builder()
          .authority(role)
          .build();
  }
}
