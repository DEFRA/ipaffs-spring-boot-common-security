package uk.gov.defra.tracesx.common.security;

import static java.util.Collections.EMPTY_LIST;
import static java.util.Collections.singletonList;
import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import uk.gov.defra.tracesx.common.permissions.PermissionsClient;

@RunWith(MockitoJUnitRunner.class)
public class PermissionsFilterTest {

  private static final String READ = "read";
  private static final String PERMISSIONS_ARE_EMPTY = "Permissions are empty";
  private static final String ECONOMIC_OPERATOR_READ = "myservice.read";

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private FilterChain filterChain;

  @Mock
  private Authentication authentication;

  @Mock
  private UserDetails userDetails;

  @Mock
  private PermissionsClient permissionsClient;

  @Mock
  private AuthenticationFacade authenticationFacade;

  @InjectMocks
  private PermissionsFilter permissionsFilter;

  private List<String> perms = singletonList(READ);
  private List<GrantedAuthority> grantedAuthoritiesList = new ArrayList<>();
  private Collection grantedAuthorities = singletonList(new SimpleGrantedAuthority(READ));

  @Before
  public void setup() {
    grantedAuthoritiesList.add(new SimpleGrantedAuthority(ECONOMIC_OPERATOR_READ));
    when(permissionsClient.permissionsList(any(), any())).thenReturn(perms);
    when(authenticationFacade.getAuthentication()).thenReturn(authentication);
    when(authentication.getDetails()).thenReturn(userDetails);
    when(userDetails.getAuthorities()).thenReturn(grantedAuthorities);
  }

  @Test
  public void filterAddsAuthoritiesToCurrentSecurityContext() throws Exception {
    when(permissionsClient.permissionsList(any(), any())).thenReturn(singletonList(ECONOMIC_OPERATOR_READ));

    permissionsFilter.doFilterInternal(request, response, filterChain);

    verify(authenticationFacade).replaceAuthorities(grantedAuthoritiesList);
  }

  @Test
  public void filterReturnsUnauthorisedResponseWhenUserHasNoPermissions() throws Exception {
    when(permissionsClient.permissionsList(any(), any())).thenReturn(EMPTY_LIST);

    permissionsFilter.doFilterInternal(request, response, filterChain);

    verify(response).sendError(SC_UNAUTHORIZED, PERMISSIONS_ARE_EMPTY);
  }
}
