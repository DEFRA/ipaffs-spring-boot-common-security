package uk.gov.defra.tracesx.common.security.filter;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.util.matcher.RequestMatcher;
import uk.gov.defra.tracesx.common.exceptions.PermissionsAuthenticationException;
import uk.gov.defra.tracesx.common.permissions.PermissionsCache;
import uk.gov.defra.tracesx.common.security.IdTokenAuthentication;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;

public class PermissionsFilter extends StatelessAuthenticationProcessingFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(PermissionsFilter.class);

  static final String ROLES_ARE_EMPTY = "Roles are empty";
  static final String PERMISSIONS_ARE_EMPTY = "Permissions are empty";
  private static final String AUTHENTICATION_NOT_FOUND =
      "Authentication not found on security context.";

  private final PermissionsCache permissionsCache;

  PermissionsFilter(String defaultFilterProcessesUrl, PermissionsCache permissionsCache) {
    super(defaultFilterProcessesUrl);
    this.permissionsCache = permissionsCache;
  }

  public PermissionsFilter(
      RequestMatcher requiresAuthenticationRequestMatcher, PermissionsCache permissionsCache) {
    super(requiresAuthenticationRequestMatcher);
    this.permissionsCache = permissionsCache;
  }

  @Override
  public Authentication attemptAuthentication(
      HttpServletRequest request, HttpServletResponse response) {

    List<String> roles = getRoles();
    if (roles.isEmpty()) {
      LOGGER.error(ROLES_ARE_EMPTY);
      throw new PermissionsAuthenticationException(ROLES_ARE_EMPTY);
    }

    List<GrantedAuthority> permissions = getPermissions(request, roles);
    if (permissions.isEmpty()) {
      LOGGER.error(PERMISSIONS_ARE_EMPTY);
      throw new PermissionsAuthenticationException(PERMISSIONS_ARE_EMPTY);
    }

    return replaceAuthorities(permissions);
  }

  private List<String> getRoles() {
    Authentication authentication = getAuthentication();
    UserDetails userDetails = (UserDetails) authentication.getDetails();
    if (userDetails != null) {
      return userDetails.getAuthorities().stream()
          .map(GrantedAuthority::getAuthority)
          .toList();
    }
    return Collections.emptyList();
  }

  private List<GrantedAuthority> getPermissions(HttpServletRequest request, List<String> roles) {
    final String authorisationToken = request.getHeader(AUTHORIZATION);
    return roles.stream()
        .map(role -> permissionsCache.permissionsList(role, authorisationToken))
        .flatMap(List::stream)
        .distinct()
        .<GrantedAuthority>map(SimpleGrantedAuthority::new)
        .toList();
  }

  public IdTokenAuthentication getAuthentication() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication instanceof IdTokenAuthentication idToken) {
      return idToken;
    }
    LOGGER.error(
        "Could not find an instance of {} on the Spring Security Context. Actual: {}",
        IdTokenAuthentication.class,
        authentication != null ? authentication.getClass() : null);
    throw new AuthenticationCredentialsNotFoundException(AUTHENTICATION_NOT_FOUND);
  }

  private Authentication replaceAuthorities(List<GrantedAuthority> permissions) {
    IdTokenAuthentication originalAuthentication = getAuthentication();
    IdTokenUserDetails originalUserDetails =
        (IdTokenUserDetails) originalAuthentication.getDetails();

    IdTokenUserDetails newUserDetails = IdTokenUserDetails.builder()
        .userObjectId(originalUserDetails.getUserObjectId())
        .displayName(originalUserDetails.getDisplayName())
        .idToken(originalUserDetails.getIdToken())
        .username(originalUserDetails.getUsername())
        .authorities(permissions)
        .customerId(originalUserDetails.getCustomerId())
        .customerOrganisationId(originalUserDetails.getCustomerOrganisationId())
        .centralCompetentAuthority(originalUserDetails.getCentralCompetentAuthority())
        .build();
    return new IdTokenAuthentication(newUserDetails);
  }
}
