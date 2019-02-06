package uk.gov.defra.tracesx.common.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class RoleToAuthorityMapperTest {

  private RoleToAuthorityMapper mapper = new RoleToAuthorityMapper();

  @Test
  public void mapRole_inIdentityFormat_createOrganisationGrantedAuthority() {
    List<String> roles = Arrays.asList("AD_ROLE", "organisation_id:identity_role:3");
    List<GrantedAuthority> authorities = mapper.mapRoles(roles);
    assertThat(authorities).hasSize(2);
    assertThat(authorities.get(0))
        .isInstanceOf(SimpleGrantedAuthority.class)
        .isEqualTo(new SimpleGrantedAuthority("AD_ROLE"));
    assertThat(authorities.get(1))
        .isInstanceOf(OrganisationGrantedAuthority.class)
        .isEqualTo(
            OrganisationGrantedAuthority.builder()
                .organisation("organisation_id")
                .authority("identity_role")
                .status("3")
                .build());
  }
}
