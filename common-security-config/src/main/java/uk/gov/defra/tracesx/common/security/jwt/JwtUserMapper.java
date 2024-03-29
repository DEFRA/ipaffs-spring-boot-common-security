package uk.gov.defra.tracesx.common.security.jwt;

import static uk.gov.defra.tracesx.common.security.jwt.JwtContants.ROLES;

import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import uk.gov.defra.tracesx.common.exceptions.InsSecurityException;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.RoleToAuthorityMapper;

@Component
public class JwtUserMapper {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwtUserMapper.class);
  private static final String SUB = "sub";
  private static final String CUSTOMER_ID = "customer_id";
  private static final String CUSTOMER_ORGANISATION_ID = "customer_organisation_id";
  private static final String CENTRAL_COMPETENT_AUTHORITY = "cca";
  private static final String FAMILY_NAME = "family_name";
  private static final String GIVEN_NAME = "given_name";

  private final RoleToAuthorityMapper roleToAuthorityMapper;

  @Autowired
  public JwtUserMapper(RoleToAuthorityMapper roleToAuthorityMapper) {
    this.roleToAuthorityMapper = roleToAuthorityMapper;
  }

  public IdTokenUserDetails createUser(Map<String, Object> decoded, String idToken) {
    return IdTokenUserDetails.builder()
        .idToken(idToken)
        .displayName(getClaim(GIVEN_NAME, decoded, false) + " "
            + getClaim(FAMILY_NAME, decoded, false))
        .username(getClaim(SUB, decoded, true))
        .userObjectId(getClaim(SUB, decoded, true))
        .customerId(getClaim(CUSTOMER_ID, decoded, false))
        .authorities(getAuthorities(decoded))
        .customerOrganisationId(getClaim(CUSTOMER_ORGANISATION_ID, decoded, false))
        .centralCompetentAuthority(getClaim(CENTRAL_COMPETENT_AUTHORITY, decoded, false))
        .build();
  }

  private String getClaim(String claimName, Map<String, Object> body, boolean isRequired) {
    String value = (String) body.get(claimName);
    if (StringUtils.isEmpty(value) && isRequired) {
      LOGGER.error("The JWT token is missing the claim '{}'", claimName);
      throw missingRequiredClaims();
    }
    return value;
  }

  private List<GrantedAuthority> getAuthorities(Map<String, Object> body) {
    if (!body.containsKey("roles")) {
      LOGGER.error("The JWT token is missing the claim 'roles'");
      throw missingRequiredClaims();
    }

    Object rolesObj = body.get(ROLES);

    if (!(rolesObj instanceof List)) {
      LOGGER.error("The JWT token does not contain a list of 'roles'");
      throw missingRequiredClaims();
    }

    List<String> roles = (List) rolesObj;
    return roleToAuthorityMapper.mapRoles(roles);
  }

  private InsSecurityException missingRequiredClaims() {
    return new InsSecurityException("User is missing required claims");
  }
}
