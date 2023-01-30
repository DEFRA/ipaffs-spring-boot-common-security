package uk.gov.defra.tracesx.common.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
public class InsSecurityException extends RuntimeException {

  public InsSecurityException(String message) {
    super(message);
  }
}
