package uk.gov.defra.tracesx.common.exceptions;

import org.springframework.security.core.AuthenticationException;

public class JwtAuthenticationException extends AuthenticationException {

  public JwtAuthenticationException(String message) {
    super(message);
  }
}
