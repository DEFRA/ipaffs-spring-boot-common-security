package uk.gov.defra.tracesx.common.security.jwks;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.security.Key;

@Builder
@Getter
@EqualsAndHashCode
public class KeyAndClaims {
  private String iss;
  private String aud;
  private Key key;
}
