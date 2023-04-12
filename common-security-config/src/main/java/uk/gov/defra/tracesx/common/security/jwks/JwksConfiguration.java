package uk.gov.defra.tracesx.common.security.jwks;

import java.net.URL;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;

@Getter
@Builder
@EqualsAndHashCode
public class JwksConfiguration {
  private URL jwksUrl;
  private String audience;
  private String issuer;
}
