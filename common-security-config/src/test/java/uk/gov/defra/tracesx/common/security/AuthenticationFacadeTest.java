package uk.gov.defra.tracesx.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

@RunWith(MockitoJUnitRunner.class)
public class AuthenticationFacadeTest {

  private final SecurityContextImpl securityContext = new SecurityContextImpl();
  private static final String ECONOMICOPERATOR_READ = "economicoperator.read";

  @Mock
  private IdTokenAuthentication authentication;

  @InjectMocks
  private AuthenticationFacade authenticationFacade;

  @Before
  public void setup() {
    securityContext.setAuthentication(authentication);
    SecurityContextHolder.setContext(securityContext);
    authenticationFacade = new AuthenticationFacade();
  }

  @Test
  public void testWhenGetAuthenticationThenReturnsAuthentication() {

    final Authentication facadeAuthentication = authenticationFacade.getAuthentication();
    assertThat(facadeAuthentication).isNotNull();
    assertThat(facadeAuthentication).isEqualTo(authentication);
  }

  @Test
  public void testWhenReplaceAuthoritiesThenGetAuthorityReturnsNewPermissions() {
    when(authentication.getDetails()).thenReturn(IdTokenUserDetailsFixture.create());

    GrantedAuthority authority = new SimpleGrantedAuthority(ECONOMICOPERATOR_READ);
    List<GrantedAuthority> grantedAuthoritiesList = Collections.singletonList(authority);


    authenticationFacade.replaceAuthorities(grantedAuthoritiesList);

    IdTokenUserDetails expected = IdTokenUserDetailsFixture.create(grantedAuthoritiesList);

    Authentication result = securityContext.getAuthentication();
    IdTokenUserDetails userDetails = (IdTokenUserDetails) result.getDetails();

    assertThat(userDetails).isEqualTo(expected);

  }
}