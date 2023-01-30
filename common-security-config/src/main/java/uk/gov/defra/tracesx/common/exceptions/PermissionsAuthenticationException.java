package uk.gov.defra.tracesx.common.exceptions;

import org.springframework.security.core.AuthenticationException;

public class PermissionsAuthenticationException extends AuthenticationException {

  public PermissionsAuthenticationException(String explanation) {
    super(explanation);
  }
}
