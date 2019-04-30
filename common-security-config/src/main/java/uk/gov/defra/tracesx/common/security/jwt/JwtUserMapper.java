package uk.gov.defra.tracesx.common.security.jwt;

import static uk.gov.defra.tracesx.common.security.jwt.JwtContants.ROLES;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import uk.gov.defra.tracesx.common.exceptions.InsSecurityException;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.RoleToAuthorityMapper;

import java.util.List;
import java.util.Map;

@Component
public class JwtUserMapper {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwtUserMapper.class);
  private static final String SUB = "sub";

  private final RoleToAuthorityMapper roleToAuthorityMapper;

  @Autowired
  public JwtUserMapper(RoleToAuthorityMapper roleToAuthorityMapper) {
    this.roleToAuthorityMapper = roleToAuthorityMapper;
  }

  IdTokenUserDetails createUser(Map<String, Object> decoded, String idToken) {
    return IdTokenUserDetails.builder()
        .idToken(idToken)
        .displayName(getRequiredClaim(SUB, decoded))
        .username(getRequiredClaim(SUB, decoded))
        .userObjectId(getRequiredClaim(SUB, decoded))
        .authorities(getAuthorities(decoded))
        .build();
  }

  private String getRequiredClaim(String claimName, Map<String, Object> body) {
    String value = (String) body.get(claimName);
    if (StringUtils.isEmpty(value)) {
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
