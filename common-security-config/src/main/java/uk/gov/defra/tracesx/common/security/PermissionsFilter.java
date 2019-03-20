package uk.gov.defra.tracesx.common.security;

import static java.util.stream.Collectors.toList;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import uk.gov.defra.tracesx.common.permissions.PermissionsCache;

@Component
public class PermissionsFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(PermissionsFilter.class);

  static final String ROLES_ARE_EMPTY = "Roles are empty";
  static final String PERMISSIONS_ARE_EMPTY = "Permissions are empty";

  private final AuthenticationFacade authenticationFacade;

  private final PermissionsCache permissionsCache;

  public PermissionsFilter(
      AuthenticationFacade authenticationFacade,
      PermissionsCache permissionsCache) {
    this.authenticationFacade = authenticationFacade;
    this.permissionsCache = permissionsCache;
  }

  @Override
  public void doFilterInternal(
      final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
      throws IOException, ServletException {

    List<String> roles = getRoles();
    if (roles.isEmpty()) {
      sendUnauthorisedResponse(response, ROLES_ARE_EMPTY);
      return;
    }

    List<GrantedAuthority> permissions = getPermissions(request, roles);
    if (permissions.isEmpty()) {
      sendUnauthorisedResponse(response, PERMISSIONS_ARE_EMPTY);
      return;
    }

    authenticationFacade.replaceAuthorities(permissions);
    chain.doFilter(request, response);
  }

  private List<String> getRoles() {
    Authentication authentication = authenticationFacade.getAuthentication();
    UserDetails userDetails = (UserDetails) authentication.getDetails();
    if (userDetails != null) {
      return userDetails.getAuthorities().stream()
          .map(GrantedAuthority::getAuthority)
          .collect(toList());
    }
    return Collections.emptyList();
  }

  private List<GrantedAuthority> getPermissions(HttpServletRequest request, List<String> roles) {
    final String authorisationToken = request.getHeader(AUTHORIZATION);
    return roles.stream()
        .map(role -> permissionsCache.permissionsList(role, authorisationToken))
        .flatMap(List::stream)
        .distinct()
        .map(SimpleGrantedAuthority::new)
        .collect(toList());
  }

  private void sendUnauthorisedResponse(HttpServletResponse httpResponse, String errorMessage) throws IOException {
    LOGGER.warn("Unauthorised request: {}", errorMessage);
    httpResponse.sendError(SC_UNAUTHORIZED, errorMessage);
  }
}
