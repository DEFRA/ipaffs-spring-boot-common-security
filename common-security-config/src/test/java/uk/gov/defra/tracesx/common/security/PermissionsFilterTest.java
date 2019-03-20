package uk.gov.defra.tracesx.common.security;

import static javax.servlet.http.HttpServletResponse.SC_UNAUTHORIZED;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import uk.gov.defra.tracesx.common.permissions.PermissionsCache;

@RunWith(MockitoJUnitRunner.class)
public class PermissionsFilterTest {

  private static final String ROLE = "ROLE";
  private static final String BEARER_TOKEN = "Bearer TOKEN";
  private static final String PERMISSION = "PERMISSION";

  @Mock private HttpServletRequest request;

  @Mock private HttpServletResponse response;

  @Mock private FilterChain filterChain;

  @Mock private Authentication authentication;

  @Mock private UserDetails userDetails;

  @Mock private PermissionsCache permissionsCache;

  @Mock private AuthenticationFacade authenticationFacade;

  @InjectMocks private PermissionsFilter permissionsFilter;

  @After
  public void after() {
    verify(authenticationFacade).getAuthentication();
    verify(authentication).getDetails();
    verifyNoMoreInteractions(
        request,
        response,
        filterChain,
        authentication,
        userDetails,
        permissionsCache,
        authenticationFacade);
  }

  private void mockAuthenticationSingleton(List<GrantedAuthority> authorities) {
    when(userDetails.getAuthorities()).thenReturn((Collection) authorities);
    when(authentication.getDetails()).thenReturn(userDetails);
    when(authenticationFacade.getAuthentication()).thenReturn(authentication);
  }

  @Test
  public void doFilter_noUserDetails_sendErrorUnauthorized() throws Exception {
    when(authentication.getDetails()).thenReturn(null);
    when(authenticationFacade.getAuthentication()).thenReturn(authentication);

    permissionsFilter.doFilterInternal(request, response, filterChain);

    verify(response)
        .sendError(
            eq(SC_UNAUTHORIZED),
            argThat(message -> message.contains(PermissionsFilter.ROLES_ARE_EMPTY)));
  }

  @Test
  public void doFilter_userHasNoRoles_sendErrorUnauthorized() throws Exception {
    mockAuthenticationSingleton(Collections.emptyList());

    permissionsFilter.doFilterInternal(request, response, filterChain);

    verify(userDetails).getAuthorities();
    verify(response)
        .sendError(
            eq(SC_UNAUTHORIZED),
            argThat(message -> message.contains(PermissionsFilter.ROLES_ARE_EMPTY)));
  }

  @Test
  public void doFilter_userHasNoPermissions_sendErrorUnauthorized() throws Exception {
    mockAuthenticationSingleton(Collections.singletonList(new SimpleGrantedAuthority(ROLE)));
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(permissionsCache.permissionsList(eq(ROLE), eq(BEARER_TOKEN)))
        .thenReturn(Collections.emptyList());

    permissionsFilter.doFilterInternal(request, response, filterChain);

    verify(userDetails).getAuthorities();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(eq(ROLE), eq(BEARER_TOKEN));
    verify(response)
        .sendError(
            eq(SC_UNAUTHORIZED),
            argThat(message -> message.contains(PermissionsFilter.PERMISSIONS_ARE_EMPTY)));
  }

  @Test
  public void doFilter_userHasSingleRoleAndPermission_callsFilterChain() throws Exception {
    mockAuthenticationSingleton(Collections.singletonList(new SimpleGrantedAuthority(ROLE)));
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(permissionsCache.permissionsList(eq(ROLE), eq(BEARER_TOKEN)))
        .thenReturn(Collections.singletonList(PERMISSION));

    permissionsFilter.doFilterInternal(request, response, filterChain);

    verify(userDetails).getAuthorities();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(eq(ROLE), eq(BEARER_TOKEN));
    verify(authenticationFacade)
        .replaceAuthorities(eq(Collections.singletonList(new SimpleGrantedAuthority(PERMISSION))));
    verify(filterChain).doFilter(request, response);
  }

  @Test
  public void doFilter_userHasMultipleRolesAndPermissions_callsFilterChain() throws Exception {
    final String role1 = "ROLE1";
    final String role2 = "ROLE2";
    List<String> ROLES = Arrays.asList(role1, role2);
    List<String> PERMISSIONS_ROLE1 = Arrays.asList("role1.permission1", "role1.permission2");
    List<String> PERMISSIONS_ROLE2 = Arrays.asList("role2.permission1", "role2.permission2");
    mockAuthenticationSingleton(
        ROLES.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(permissionsCache.permissionsList(eq(role1), eq(BEARER_TOKEN)))
        .thenReturn(PERMISSIONS_ROLE1);
    when(permissionsCache.permissionsList(eq(role2), eq(BEARER_TOKEN)))
        .thenReturn(PERMISSIONS_ROLE2);

    permissionsFilter.doFilterInternal(request, response, filterChain);

    List<GrantedAuthority> expectedAuthorities =
        Stream.of(PERMISSIONS_ROLE1, PERMISSIONS_ROLE2)
            .flatMap(List::stream)
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());
    verify(userDetails).getAuthorities();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(eq(role1), eq(BEARER_TOKEN));
    verify(permissionsCache).permissionsList(eq(role2), eq(BEARER_TOKEN));
    verify(authenticationFacade)
        .replaceAuthorities(argThat(authorities -> authorities.containsAll(expectedAuthorities)));
    verify(filterChain).doFilter(request, response);
  }
}
