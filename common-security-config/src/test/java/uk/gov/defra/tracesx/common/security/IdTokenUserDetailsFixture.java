package uk.gov.defra.tracesx.common.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

public class IdTokenUserDetailsFixture {

  public static final String USER_OBJECT_ID = "e9f6447d-2979-4322-8e52-307dafdef649";
  public static final String ID_TOKEN = "adfgsdf.dfgsdrgerg.dfgdfgd";
  public static final String DISPLAY_NAME = "Joseph William Token";
  public static final String USERNAME = "jtoken@tenant.com";
  public static final List<String> ROLES = Arrays.asList("ROLE1", "ROLE2");
  public static final List<GrantedAuthority> AUTHORITIES = Collections.unmodifiableList(
      ROLES.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

  public static IdTokenUserDetails create() {
    return create(AUTHORITIES);
  }

  public static IdTokenUserDetails create(List<GrantedAuthority> authorities) {
    return IdTokenUserDetails.builder()
        .idToken(ID_TOKEN)
        .authorities(authorities)
        .userObjectId(USER_OBJECT_ID)
        .displayName(DISPLAY_NAME)
        .username(USERNAME)
        .build();
  }

}
