package uk.gov.defra.tracesx.common.security;

import static java.util.Collections.EMPTY_LIST;
import static java.util.stream.Collectors.toList;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.io.IOException;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import uk.gov.defra.tracesx.common.service.PermissionsService;

@Component
public class PermissionsFilter extends OncePerRequestFilter {

  private static final String ROLES_ARE_EMPTY = "Roles are empty";
  private static final String PERMISSIONS_ARE_EMPTY = "Permissions are empty";

  @Autowired
  private AuthenticationFacade authenticationFacade;

  @Autowired
  private PermissionsService permissionsService;

  private static final Logger LOGGER = LoggerFactory.getLogger(PermissionsFilter.class);

  @Override
  public void doFilterInternal(
      final HttpServletRequest request, final HttpServletResponse response, final FilterChain chain)
      throws IOException, ServletException {
    List<String> roles = EMPTY_LIST;
    final Authentication authentication = authenticationFacade.getAuthentication();
    final UserDetails userDetails = (UserDetails) authentication.getPrincipal();
    if (userDetails != null) {
      roles =
          userDetails
              .getAuthorities()
              .stream()
              .map(GrantedAuthority::getAuthority)
              .collect(toList());
    }
    if (roles.isEmpty()) {
      LOGGER.error(ROLES_ARE_EMPTY);
      sendUnauthorisedResponse(response, ROLES_ARE_EMPTY);
      return;
    }
    final String authorisationToken = request.getHeader(AUTHORIZATION);
    final List<GrantedAuthority> perms =
        roles
            .stream()
            .map(role -> permissionsService.permissionsList(role, authorisationToken))
            .flatMap(List::stream)
            .distinct()
            .map(SimpleGrantedAuthority::new)
            .collect(toList());

    if (perms.isEmpty()) {
      LOGGER.error(PERMISSIONS_ARE_EMPTY);
      sendUnauthorisedResponse(response, PERMISSIONS_ARE_EMPTY);
      return;
    }
    authenticationFacade.replaceAuthorities(perms);
    chain.doFilter(request, response);
  }

  private void sendUnauthorisedResponse(HttpServletResponse httpResponse, String errorMessage)
      throws IOException {
    LOGGER.info("Unauthorised request.");
    httpResponse.sendError(SC_UNAUTHORIZED, errorMessage);
  }
}
