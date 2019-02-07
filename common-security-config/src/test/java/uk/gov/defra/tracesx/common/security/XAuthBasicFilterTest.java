package uk.gov.defra.tracesx.common.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.defra.tracesx.common.security.XAuthBasicFilter.BASIC_AUTH_HEADER_KEY;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;

@RunWith(MockitoJUnitRunner.class)
public class XAuthBasicFilterTest {

  private static final String BASIC_HEADER = "Basic dXNlcm5hbWU6cGFzc3dvcmQ=";

  @Mock
  private AuthenticationManager authenticationManager;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private FilterChain chain;

  private XAuthBasicFilter filter;

  @Before
  public void before() {
    filter = new XAuthBasicFilter(authenticationManager);
    when(request.getHeader(BASIC_AUTH_HEADER_KEY)).thenReturn(BASIC_HEADER);
  }

  @After
  public void after() {
    verifyNoMoreInteractions(authenticationManager, response, chain);
  }

  @Test
  public void doFilterInternal_does_not_require_auth_on_admin() throws Exception {
    when(request.getRequestURI()).thenReturn("/admin/info");

    filter.doFilter(request, response, chain);

    verify(chain).doFilter(request, response);
  }

  @Test
  public void doFilter_missingHeader_throwsException() throws Exception {
    when(request.getRequestURI()).thenReturn("/base");
    when(request.getHeader(BASIC_AUTH_HEADER_KEY)).thenReturn(null);

    filter.doFilter(request, response, chain);

    verify(request).getHeader(BASIC_AUTH_HEADER_KEY);
    verify(response).sendError(eq(400), anyString());
  }

  @Test
  public void doFilter_notBasicAuth_throwsException() throws Exception {
    when(request.getHeader(BASIC_AUTH_HEADER_KEY)).thenReturn("Bearer asdfghjkl");
    when(request.getRequestURI()).thenReturn("/base");

    filter.doFilter(request, response, chain);

    verify(request).getHeader(BASIC_AUTH_HEADER_KEY);
    verify(response).sendError(eq(400), anyString());
  }

  @Test
  public void doFilter_basicAuthInvalidEncoding_throwsException() throws Exception {
    when(request.getHeader(BASIC_AUTH_HEADER_KEY)).thenReturn("Basic !@£$%^&*()");
    when(request.getRequestURI()).thenReturn("/base");

    filter.doFilter(request, response, chain);

    verify(request).getHeader(BASIC_AUTH_HEADER_KEY);
    verify(response).sendError(eq(400), anyString());
  }

  @Test
  public void doFilter_basicAuthInvalidFormat_throwsException() throws Exception {
    when(request.getHeader(BASIC_AUTH_HEADER_KEY)).thenReturn("Basic bm8gY29sb24gc2VwZXJhdG9y");
    when(request.getRequestURI()).thenReturn("/base");

    filter.doFilter(request, response, chain);

    verify(request).getHeader(BASIC_AUTH_HEADER_KEY);
    verify(response).sendError(eq(400), anyString());
  }

  @Test
  public void doFilter_invalidCredentials_throwsException() throws Exception {
    when(request.getHeader(BASIC_AUTH_HEADER_KEY)).thenReturn(BASIC_HEADER);
    when(request.getRequestURI()).thenReturn("/base");
    when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("Invalid credentials"));

    filter.doFilter(request, response, chain);

    verify(authenticationManager).authenticate(any());
    verify(request).getHeader(BASIC_AUTH_HEADER_KEY);
    verify(response).sendError(eq(400), anyString());
  }

  @Test
  public void doFilter_validCredentials_succeeds() throws Exception {
    when(request.getRequestURI()).thenReturn("/base");
    when(request.getHeader(BASIC_AUTH_HEADER_KEY)).thenReturn(BASIC_HEADER);

    filter.doFilter(request, response, chain);

    verify(authenticationManager).authenticate(any());
    verify(request).getHeader(BASIC_AUTH_HEADER_KEY);
    verify(chain).doFilter(request, response);
  }

}
