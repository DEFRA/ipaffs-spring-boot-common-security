package uk.gov.defra.tracesx.common.security.filter;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class StatelessAuthenticationProcessingFilter
    extends AbstractAuthenticationProcessingFilter {

  protected StatelessAuthenticationProcessingFilter(String defaultFilterProcessesUrl) {
    super(defaultFilterProcessesUrl);
  }

  protected StatelessAuthenticationProcessingFilter(
      RequestMatcher requiresAuthenticationRequestMatcher) {
    super(requiresAuthenticationRequestMatcher);
  }

  // Customized version of spring security filter, to remove session state calls and events
  @Override
  public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain)
      throws IOException, ServletException {

    HttpServletRequest request = (HttpServletRequest) req;
    HttpServletResponse response = (HttpServletResponse) res;

    if (!requiresAuthentication(request, response)) {
      chain.doFilter(request, response);
      return;
    }

    Authentication authResult;

    try {
      authResult = attemptAuthentication(request, response);
      if (authResult == null) {
        return;
      }
    } catch (AuthenticationException failed) {
      unsuccessfulAuthentication(request, response, failed);
      return;
    }

    // Authentication success
    SecurityContextHolder.getContext().setAuthentication(authResult);

    chain.doFilter(request, response);
  }
}
