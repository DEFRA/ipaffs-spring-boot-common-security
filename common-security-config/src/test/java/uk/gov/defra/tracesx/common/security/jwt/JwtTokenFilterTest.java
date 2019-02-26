package uk.gov.defra.tracesx.common.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.core.context.SecurityContextHolder;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenFilter;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;

@RunWith(MockitoJUnitRunner.class)
public class JwtTokenFilterTest {

  private static final String TOKEN = "asdf.asdf.asdf";

  @Mock
  private JwtTokenValidator jwtTokenValidator;

  @Mock
  private IdTokenUserDetails userDetails;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private FilterChain chain;

  private JwtTokenFilter filter;

  @Before
  public void before() {
    filter = new JwtTokenFilter(jwtTokenValidator);
    SecurityContextHolder.clearContext();
  }

  @After
  public void after() {
    verifyNoMoreInteractions(jwtTokenValidator, response, chain);
  }

  @Test
  public void doFilter_withCorrectHeader_setsAuthenticationOnContext() throws Exception {
    when(request.getHeader("Authorization")).thenReturn("Bearer " + TOKEN);
    when(jwtTokenValidator.validateToken(TOKEN)).thenReturn(userDetails);
    filter.doFilter(request, response, chain);
    assertThat(SecurityContextHolder.getContext().getAuthentication().getDetails()).isEqualTo(userDetails);
    verify(jwtTokenValidator).validateToken(TOKEN);
    verify(chain).doFilter(request, response);
  }

  @Test
  public void doFilter_withLowercaseAuthorizationType_setsAuthenticationOnContext() throws Exception {
    when(request.getHeader("Authorization")).thenReturn("bearer " + TOKEN);
    when(jwtTokenValidator.validateToken(TOKEN)).thenReturn(userDetails);
    filter.doFilter(request, response, chain);
    assertThat(SecurityContextHolder.getContext().getAuthentication().getDetails()).isEqualTo(userDetails);
    verify(jwtTokenValidator).validateToken(TOKEN);
    verify(chain).doFilter(request, response);
  }

  @Test
  public void doFilter_withIncorrectAuthorizationType_respondsWith401Error() throws Exception {
    when(request.getHeader("Authorization")).thenReturn("Basic " + TOKEN);
    filter.doFilter(request, response, chain);
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing credentials");
  }

  @Test
  public void doFilter_withNoAuthorizationHeader_respondsWith401Error() throws Exception {
    when(request.getHeader("Authorization")).thenReturn(null);
    filter.doFilter(request, response, chain);
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    verify(response).sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing credentials");
  }

}
