package uk.gov.defra.tracesx.common.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;

class RoleToAuthorityMapperTest {

  private RoleToAuthorityMapper mapper = new RoleToAuthorityMapper();

  @Test
  void mapRole_inIdentityFormat_createOrganisationGrantedAuthority() {
    List<String> roles = Arrays.asList("AD_ROLE");
    List<GrantedAuthority> authorities = mapper.mapRoles(roles);
    assertThat(authorities).hasSize(1);
    assertThat(authorities.get(0))
            .isInstanceOf(OrganisationGrantedAuthority.class)
                 .isEqualTo(new OrganisationGrantedAuthority("AD_ROLE"));
  }
}
