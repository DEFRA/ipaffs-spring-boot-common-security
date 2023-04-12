package uk.gov.defra.tracesx.common.security.jwks;

import java.security.Key;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Builder
@Getter
@EqualsAndHashCode
public class KeyAndClaims {
  private String iss;
  private String aud;
  private Key key;
}
