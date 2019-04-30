package uk.gov.defra.tracesx.common.security.jwks;

import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;

import java.net.URL;

@Getter
@Builder
@EqualsAndHashCode
public class JwksConfiguration {
  private URL jwksUrl;
  private String audience;
  private String issuer;
}
