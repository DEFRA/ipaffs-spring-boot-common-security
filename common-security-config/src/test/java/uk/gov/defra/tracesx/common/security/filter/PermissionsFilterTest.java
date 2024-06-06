package uk.gov.defra.tracesx.common.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.defra.tracesx.common.security.filter.PermissionsFilter.PERMISSIONS_ARE_EMPTY;
import static uk.gov.defra.tracesx.common.security.filter.PermissionsFilter.ROLES_ARE_EMPTY;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
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

@RunWith(MockitoJUnitRunner.class)
public class PermissionsFilterTest {

  private static final String ROLE = "ROLE";
  private static final String BEARER_TOKEN = "Bearer TOKEN";
  private static final String PERMISSION = "PERMISSION";
  private static final String CUSTOMER_ORGANISATION_ID =  "bb55e17d-f6c8-40df-9d8f-19a7d9f5bdcc";
  private static final String CUSTOMER_ID =  "ee55e17d-f6c8-40df-9d8f-19a7d9f5bd8b";

  @Mock private HttpServletRequest request;

  @Mock private HttpServletResponse response;

  @Mock
  private IdTokenAuthentication authentication;

  @Mock
  private IdTokenUserDetails userDetails;

  @Mock private PermissionsCache permissionsCache;

  private PermissionsFilter permissionsFilter;

  @Before
  public void before() {
    permissionsFilter = new PermissionsFilter("/url", permissionsCache);
  }

  @After
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
  public void doFilter_noUserDetails_throwsAuthenticationException() {
    when(authentication.getDetails()).thenReturn(null);
    SecurityContextHolder.getContext().setAuthentication(authentication);

    assertThatExceptionOfType(AuthenticationException.class)
        .isThrownBy(() -> permissionsFilter.attemptAuthentication(request, response))
        .withMessageContaining(ROLES_ARE_EMPTY);

    verify(authentication, times(1)).getDetails();
  }

  @Test
  public void doFilter_userHasNoRoles_throwsAuthenticationException() {
    mockAuthenticationSingleton(Collections.emptyList());

    assertThatExceptionOfType(AuthenticationException.class)
        .isThrownBy(() -> permissionsFilter.attemptAuthentication(request, response))
        .withMessageContaining(ROLES_ARE_EMPTY);

    verify(authentication, times(1)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
  }

  @Test
  public void doFilter_userHasNoPermissions_throwsAuthenticationException() {
    mockAuthenticationSingleton(Collections.singletonList(new SimpleGrantedAuthority(ROLE)));
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(permissionsCache.permissionsList(eq(ROLE), eq(BEARER_TOKEN)))
        .thenReturn(Collections.emptyList());

    assertThatExceptionOfType(AuthenticationException.class)
        .isThrownBy(() -> permissionsFilter.attemptAuthentication(request, response))
        .withMessageContaining(PERMISSIONS_ARE_EMPTY);

    verify(authentication, times(1)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(eq(ROLE), eq(BEARER_TOKEN));
  }

  @Test
  public void doFilter_userHasSingleRoleAndPermission_amendsAuthentication() {
    mockAuthenticationSingleton(Collections.singletonList(new SimpleGrantedAuthority(ROLE)));
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(permissionsCache.permissionsList(eq(ROLE), eq(BEARER_TOKEN)))
            .thenReturn(Collections.singletonList(PERMISSION));

    Authentication amendedAuthentication = permissionsFilter.attemptAuthentication(request, response);
    GrantedAuthority expectedAuthority = new SimpleGrantedAuthority(PERMISSION);
    assertThat((Collection<GrantedAuthority>) amendedAuthentication.getAuthorities()).containsOnly(expectedAuthority);

    verify(authentication, times(2)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
    verify(userDetails, times(1)).getCustomerOrganisationId();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(eq(ROLE), eq(BEARER_TOKEN));
  }

  @Test
  public void doFilter_userHasMultipleRolesAndPermissions_amendsAuthentication() {
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

    Authentication amendedAuthentication = permissionsFilter.attemptAuthentication(request, response);

    List<GrantedAuthority> expectedAuthorities =
        Stream.of(PERMISSIONS_ROLE1, PERMISSIONS_ROLE2)
            .flatMap(List::stream)
            .map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());

    assertThat(amendedAuthentication.getAuthorities()).containsOnlyElementsOf((Iterable) expectedAuthorities);

    verify(authentication, times(2)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
    verify(userDetails, times(1)).getCustomerOrganisationId();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache).permissionsList(eq(role1), eq(BEARER_TOKEN));
    verify(permissionsCache).permissionsList(eq(role2), eq(BEARER_TOKEN));
  }

  @Test
  public void doFilter_userHasOrganisationAndPermission_amendsAuthentication() {
    mockAuthenticationSingleton(Collections.emptyList());
    OrganisationGrantedAuthority organisationGrantedAuthority =
            OrganisationGrantedAuthority.builder().authority(ROLE).build();
    List<String> organisations = Arrays.asList("Organisation1");

    SecurityContextHolder.getContext().setAuthentication(authentication);
    when(authentication.getDetails()).thenReturn(userDetails);
    when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn(BEARER_TOKEN);
    when(userDetails.getAuthorities())
            .thenReturn(Arrays.asList(new SimpleGrantedAuthority(ROLE), organisationGrantedAuthority));
    when(userDetails.getCustomerOrganisationId())
            .thenReturn(CUSTOMER_ORGANISATION_ID);
    when(userDetails.getCustomerId())
            .thenReturn(CUSTOMER_ID);
    when(permissionsCache.permissionsList(eq(ROLE), eq(BEARER_TOKEN)))
            .thenReturn(Collections.singletonList(PERMISSION));

    permissionsFilter.attemptAuthentication(request, response);

    assertEquals(userDetails.getCustomerOrganisationId(), CUSTOMER_ORGANISATION_ID);
    assertEquals(userDetails.getCustomerId(), CUSTOMER_ID);

    verify(authentication, times(2)).getDetails();
    verify(userDetails, times(1)).getAuthorities();
    verify(request).getHeader(HttpHeaders.AUTHORIZATION);
    verify(permissionsCache, times(2)).permissionsList(eq(ROLE), eq(BEARER_TOKEN));
  }

  @Test
  public void getAuthentication_ThrowsAuthenticationCredentialsNotFoundException_WhenAuthenticationIsNull() {
    assertThatThrownBy(() -> permissionsFilter.getAuthentication()).isInstanceOf(AuthenticationCredentialsNotFoundException.class)
        .hasMessageContaining("Authentication not found on security context.");
  }

  @Test
  public void permissionsFilter_ReturnsSpecificInstance_WhenRequestMatcherIsDefined() {
    permissionsFilter = new PermissionsFilter(AnyRequestMatcher.INSTANCE, permissionsCache);
    assertThat(permissionsFilter).isNotNull();
  }
}
