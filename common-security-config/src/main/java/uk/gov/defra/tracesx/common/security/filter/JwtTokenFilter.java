package uk.gov.defra.tracesx.common.security.filter;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.RequestMatcher;
import uk.gov.defra.tracesx.common.security.IdTokenAuthentication;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;

public class JwtTokenFilter extends StatelessAuthenticationProcessingFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenFilter.class);

  private JwtTokenValidator jwtTokenValidator;

  public JwtTokenFilter(String defaultFilterProcessesUrl, JwtTokenValidator jwtTokenValidator) {
    super(defaultFilterProcessesUrl);
    this.jwtTokenValidator = jwtTokenValidator;
  }

  public JwtTokenFilter(
      RequestMatcher requiresAuthenticationRequestMatcher, JwtTokenValidator jwtTokenValidator) {
    super(requiresAuthenticationRequestMatcher);
    this.jwtTokenValidator = jwtTokenValidator;
  }

  @Override
  public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) {
    String token = resolveToken(req);
    if (null != token) {
      IdTokenUserDetails userDetails = jwtTokenValidator.validateToken(token);
      return new IdTokenAuthentication(userDetails);
    } else {
      LOGGER.error("A 'Bearer' token was not found on the 'Authorization' header.");
      throw new AuthenticationCredentialsNotFoundException("Missing credentials");
    }
  }

  private String resolveToken(HttpServletRequest req) {
    String bearerToken = req.getHeader("Authorization");
    if (bearerToken != null && bearerToken.toLowerCase().startsWith("bearer ")) {
      return bearerToken.substring(7);
    }
    return null;
  }
}
