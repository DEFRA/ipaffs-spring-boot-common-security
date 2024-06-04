package uk.gov.defra.tracesx.common.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;

@ExtendWith(MockitoExtension.class)
class JwtTokenFilterTest {

  private static final String TOKEN = "asdf.asdf.asdf";

  @Mock
  private JwtTokenValidator jwtTokenValidator;

  @Mock
  private IdTokenUserDetails userDetails;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  private JwtTokenFilter filter;

  @BeforeEach
  public void before() {
    filter = new JwtTokenFilter("/url", jwtTokenValidator);
    SecurityContextHolder.clearContext();
    SecurityContextHolder.createEmptyContext();
  }

  @AfterEach
  public void after() {
    verify(request).getHeader("Authorization");
    verifyNoMoreInteractions(jwtTokenValidator, request, response);
  }

  @Test
  void doFilter_withCorrectHeader_returnsAuthentication() throws Exception {
    when(request.getHeader("Authorization")).thenReturn("Bearer " + TOKEN);
    when(jwtTokenValidator.validateToken(TOKEN)).thenReturn(userDetails);
    Authentication authentication = filter.attemptAuthentication(request, response);
    assertThat(authentication.getDetails()).isEqualTo(userDetails);
    verify(jwtTokenValidator).validateToken(TOKEN);
  }

  @Test
  void doFilter_withLowercaseAuthorizationType_returnsAuthentication() throws Exception {
    when(request.getHeader("Authorization")).thenReturn("bearer " + TOKEN);
    when(jwtTokenValidator.validateToken(TOKEN)).thenReturn(userDetails);
    Authentication authentication = filter.attemptAuthentication(request, response);
    assertThat(authentication.getDetails()).isEqualTo(userDetails);
    verify(jwtTokenValidator).validateToken(TOKEN);
  }

  @Test
  void doFilter_withIncorrectAuthorizationType_throwsAuthenticationException()
      throws Exception {
    when(request.getHeader("Authorization")).thenReturn("Basic " + TOKEN);
    assertThatExceptionOfType(AuthenticationException.class)
        .isThrownBy(() -> filter.attemptAuthentication(request, response));
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }

  @Test
  void doFilter_withNoAuthorizationHeader_throwsAuthenticationException() throws Exception {
    when(request.getHeader("Authorization")).thenReturn(null);
    assertThatExceptionOfType(AuthenticationException.class)
        .isThrownBy(() -> filter.attemptAuthentication(request, response));
    assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
  }
}
