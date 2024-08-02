package uk.gov.defra.tracesx.common.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.defra.tracesx.common.security.filter.PermissionsFilter.PERMISSIONS_ARE_EMPTY;
import static uk.gov.defra.tracesx.common.security.filter.PermissionsFilter.ROLES_ARE_EMPTY;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import uk.gov.defra.tracesx.common.permissions.PermissionsCache;
import uk.gov.defra.tracesx.common.security.IdTokenAuthentication;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.OrganisationGrantedAuthority;

@ExtendWith(MockitoExtension.class)
class PermissionsFilterTest {

  private static final String ROLE = "ROLE";
  private static final String BEARER_TOKEN = "Bearer TOKEN";
  private static final String PERMISSION = "PERMISSION";
  private static final String CUSTOMER_ORGANISATION_ID = "bb55e17d-f6c8-40df-9d8f-19a7d9f5bdcc";
  private static final String CUSTOMER_ID = "ee55e17d-f6c8-40df-9d8f-19a7d9f5bd8b";

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private IdTokenAuthentication authentication;

  @Mock
  private IdTokenUserDetails userDetails;

  @Mock
  private PermissionsCache permissionsCache;

  private PermissionsFilter permissionsFilter;

  @BeforeEach
  public void before() {
    permissionsFilter = new PermissionsFilter("/url", permissionsCache);
  }

  @AfterEach
  public void after() {
    SecurityContextHolder.clearContext();
    verifyNoMoreInteractions(
        request,
        response,
        authentication,
        permissionsCache);
  }

  private void mockAuthenticationSingleton(List<GrantedAuthority> authorities) {
    when(userDetails.getAuthorities()).thenReturn(authorities);
    when(authentication.getDetails()).thenReturn(userDetails);
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }

  @Test
  void doFilter_noUserDetails_throwsAuthenticationException() {
    when(authentication.getDetails()).thenReturn(null);
    SecurityContextHolder.getContext().setAuthentication(authentication);

    assertThatThrownBy(() -> permissionsFilter.attemptAuthentication(request, response))
        .isInstanceOf(AuthenticationException.class)
        .hasMessageContaining(ROLES_ARE_EMPTY);

    verify(authentication, times(1)).getDetails();
  }

  @Test
  void doFilter_userHasNoRoles_throwsAuthenticationException() {
    mockAuthenticationSingleton(Collections.emptyList());

    assertThatThrownBy(() -> permissionsFilter.attemptAuthentication(request, response))
        .isInstanceOf(AuthenticationException.class)
        .hasMessageContaining(ROLES_ARE_EMPTY);

    verify(authentication, times(1)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
  }

  @Test
  void doFilter_userHasNoPermissions_throwsAuthenticationException() {
    mockAuthenticationSingleton(List.of(new SimpleGrantedAuthority(ROLE)));
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(permissionsCache.permissionsList(ROLE, BEARER_TOKEN))
        .thenReturn(Collections.emptyList());

    assertThatThrownBy(() -> permissionsFilter.attemptAuthentication(request, response))
        .isInstanceOf(AuthenticationException.class)
        .hasMessageContaining(PERMISSIONS_ARE_EMPTY);

    verify(authentication, times(1)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(ROLE, BEARER_TOKEN);
  }

  @Test
  void doFilter_userHasSingleRoleAndPermission_amendsAuthentication() {
    mockAuthenticationSingleton(List.of(new SimpleGrantedAuthority(ROLE)));
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(permissionsCache.permissionsList(ROLE, BEARER_TOKEN))
        .thenReturn(List.of(PERMISSION));

    Authentication amendedAuthentication = permissionsFilter.attemptAuthentication(request,
        response);
    GrantedAuthority expectedAuthority = new SimpleGrantedAuthority(PERMISSION);
    assertThat((Collection<GrantedAuthority>) amendedAuthentication.getAuthorities()).containsOnly(
        expectedAuthority);

    verify(authentication, times(2)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
    verify(userDetails, times(1)).getCustomerOrganisationId();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(ROLE, BEARER_TOKEN);
  }

  @Test
  void doFilter_userHasMultipleRolesAndPermissions_amendsAuthentication() {
    final String role1 = "ROLE1";
    final String role2 = "ROLE2";
    List<String> ROLES = List.of(role1, role2);
    List<String> PERMISSIONS_ROLE1 = List.of("role1.permission1", "role1.permission2");
    List<String> PERMISSIONS_ROLE2 = List.of("role2.permission1", "role2.permission2");
    mockAuthenticationSingleton(
        ROLES.stream().<GrantedAuthority>map(SimpleGrantedAuthority::new).toList()
    );
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(permissionsCache.permissionsList(role1, BEARER_TOKEN))
        .thenReturn(PERMISSIONS_ROLE1);
    when(permissionsCache.permissionsList(role2, BEARER_TOKEN))
        .thenReturn(PERMISSIONS_ROLE2);

    Authentication amendedAuthentication = permissionsFilter.attemptAuthentication(request,
        response);

    List<GrantedAuthority> expectedAuthorities = Stream.of(PERMISSIONS_ROLE1, PERMISSIONS_ROLE2)
            .flatMap(List::stream)
            .<GrantedAuthority>map(SimpleGrantedAuthority::new)
            .toList();

    assertThat(amendedAuthentication.getAuthorities()).isEqualTo(expectedAuthorities);

    verify(authentication, times(2)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
    verify(userDetails, times(1)).getCustomerOrganisationId();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(role1, BEARER_TOKEN);
    verify(permissionsCache).permissionsList(role2, BEARER_TOKEN);
  }

  @Test
  void doFilter_userHasOrganisationAndPermission_amendsAuthentication() {
    mockAuthenticationSingleton(Collections.emptyList());
    OrganisationGrantedAuthority organisationGrantedAuthority =
        OrganisationGrantedAuthority.builder().authority(ROLE).build();

    SecurityContextHolder.getContext().setAuthentication(authentication);
    when(authentication.getDetails()).thenReturn(userDetails);
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(userDetails.getAuthorities())
        .thenReturn(List.of(new SimpleGrantedAuthority(ROLE), organisationGrantedAuthority));
    when(userDetails.getCustomerOrganisationId())
        .thenReturn(CUSTOMER_ORGANISATION_ID);
    when(userDetails.getCustomerId())
        .thenReturn(CUSTOMER_ID);
    when(permissionsCache.permissionsList(ROLE, BEARER_TOKEN))
        .thenReturn(List.of(PERMISSION));

    permissionsFilter.attemptAuthentication(request, response);

    assertThat(userDetails.getCustomerOrganisationId()).isEqualTo(CUSTOMER_ORGANISATION_ID);
    assertThat(userDetails.getCustomerId()).isEqualTo(CUSTOMER_ID);

    verify(authentication, times(2)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache, times(2)).permissionsList(ROLE, BEARER_TOKEN);
  }

  @Test
  void getAuthentication_ThrowsAuthenticationCredentialsNotFoundException_WhenAuthenticationIsNull() {
    assertThatThrownBy(() -> permissionsFilter.getAuthentication()).isInstanceOf(
            AuthenticationCredentialsNotFoundException.class)
        .hasMessageContaining("Authentication not found on security context.");
  }

  @Test
  void permissionsFilter_ReturnsSpecificInstance_WhenRequestMatcherIsDefined() {
    permissionsFilter = new PermissionsFilter(AnyRequestMatcher.INSTANCE, permissionsCache);
    assertThat(permissionsFilter).isNotNull();
  }
}
