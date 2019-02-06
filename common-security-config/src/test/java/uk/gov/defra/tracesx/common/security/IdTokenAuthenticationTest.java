package uk.gov.defra.tracesx.common.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class IdTokenAuthenticationTest {

  private static final String ID_TOKEN = "adfgsdf.dfgsdrgerg.dfgdfgd";
  private static final String USER_OBJECT_ID = "e9f6447d-2979-4322-8e52-307dafdef649";
  private static final List<String> ROLES = Arrays.asList("ROLE1", "ROLE2");
  private static final List<GrantedAuthority> AUTHORITIES = Collections.unmodifiableList(
      ROLES.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

  @Test
  public void testWrapsIdTokenUserDetailsCorrectly() {
    IdTokenUserDetails idTokenUserDetails = IdTokenUserDetails.builder()
        .authorities(AUTHORITIES)
        .idToken(ID_TOKEN)
        .userObjectId(USER_OBJECT_ID)
        .build();
    IdTokenAuthentication authentication = new IdTokenAuthentication(idTokenUserDetails);
    assertThat(authentication.getDetails()).isEqualTo(idTokenUserDetails);
    assertThat(authentication.getCredentials()).isEqualTo(ID_TOKEN);
    assertThat(authentication.getPrincipal()).isEqualTo(USER_OBJECT_ID);
    assertThat(authentication.isAuthenticated()).isTrue();
    assertThat(authentication.getAuthorities()).hasSameElementsAs(AUTHORITIES);
  }

}
