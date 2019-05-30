package uk.gov.defra.tracesx.common.security;

import static java.util.stream.Collectors.toList;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RoleToAuthorityMapper {

  public List<GrantedAuthority> mapRoles(List<String> roles) {
    return roles.stream().map(this::mapRole).collect(toList());
  }

  private GrantedAuthority mapRole(String role) {
    return OrganisationGrantedAuthority.builder()
          .authority(role)
          .build();
  }
}
