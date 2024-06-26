package uk.gov.defra.tracesx.common.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.security.core.GrantedAuthority;
import uk.gov.defra.tracesx.common.exceptions.InsSecurityException;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.OrganisationGrantedAuthority;
import uk.gov.defra.tracesx.common.security.RoleToAuthorityMapper;

class JwtUserMapperTest {

  private static final String USER_OBJECT_ID = "e9f6447d-2979-4322-8e52-307dafdef649";
  private static final String FAMILY_NAME = "Token";
  private static final String GIVEN_NAME = "Joseph William";
  private static final String USERNAME = "jtoken@tenant.com";
  private static final String ID_TOKEN = "adfgsdf.dfgsdrgerg.dfgdfgd";
  private static final String SUB = "e9f6447d-2979-4322-8e52-307dafdef649";
  private static final List<String> ROLES = Arrays.asList("ROLE1", "ROLE2");
  private static final String ORG_ID = "3199a90f-a670-e911-a974-000d3a28da35";
  private static final String CUSTOMER_ID = "e798a90f-a670-e911-a974-000d3a28da35";
  private static final List<String> ORG_IDS = Arrays.asList(ORG_ID);
  private static final List<GrantedAuthority> AUTHORITIES = Collections.unmodifiableList(
      ROLES.stream().map(OrganisationGrantedAuthority::new).collect(Collectors.toList()));
  private Map<String, Object> decoded;
  private RoleToAuthorityMapper roleToAuthorityMapper = new RoleToAuthorityMapper();
  private JwtUserMapper jwtUserMapper = new JwtUserMapper(roleToAuthorityMapper);

  @BeforeEach
  public void before() {
    decoded = new HashMap<>();
    decoded.put("sub", SUB);
    decoded.put("roles", ROLES);
    decoded.put("oid", USER_OBJECT_ID);
    decoded.put("family_name", FAMILY_NAME);
    decoded.put("given_name", GIVEN_NAME);
    decoded.put("upn", USERNAME);
    decoded.put("customer_id", CUSTOMER_ID);
    decoded.put("customer_organisation_id", ORG_ID);
  }

  @Test
  void createUser_allows_personal_account_with_no_org() {

    IdTokenUserDetails userDetails = IdTokenUserDetails.builder()
        .idToken(ID_TOKEN)
        .authorities(AUTHORITIES)
        .userObjectId(SUB)
        .displayName(GIVEN_NAME + " " + FAMILY_NAME)
        .username(SUB)
        .customerOrganisationId(null)
        .customerId(CUSTOMER_ID)
        .build();

    assertNotNull(userDetails);
  }

  @Test
  void createUser_fromCompleteClaims_isFullyPopulated() {
    IdTokenUserDetails user = jwtUserMapper.createUser(decoded, ID_TOKEN);
    IdTokenUserDetails expected = IdTokenUserDetails.builder()
        .idToken(ID_TOKEN)
        .authorities(AUTHORITIES)
        .userObjectId(SUB)
        .displayName(GIVEN_NAME + " " + FAMILY_NAME)
        .username(SUB)
        .customerOrganisationId(ORG_ID)
        .customerId(CUSTOMER_ID)
        .build();
    assertThat(user).isEqualTo(expected);
  }

  @Test
  void createUser_rolesIsNotAList_isFullyPopulated() {
    decoded.put("roles", "NotAList");
    assertThatExceptionOfType(InsSecurityException.class)
        .isThrownBy(() -> jwtUserMapper.createUser(decoded, ID_TOKEN));
  }

  @Test
  void createUser_BodyDoesntContainRoles_ThrowsException() {
    decoded.remove("roles");
    assertThatExceptionOfType(InsSecurityException.class)
        .isThrownBy(() -> jwtUserMapper.createUser(decoded, ID_TOKEN));
  }

  @ParameterizedTest
  @ValueSource(strings = {"sub"})
  void createUser_fromIncompleteClaims_throwsException(String missingClaim) {
    decoded.remove(missingClaim);
    assertThatExceptionOfType(InsSecurityException.class)
        .isThrownBy(() -> jwtUserMapper.createUser(decoded, ID_TOKEN));
  }
}
