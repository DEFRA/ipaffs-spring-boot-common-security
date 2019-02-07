package uk.gov.defra.tracesx.common.security.jwks;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.JwkProvider;
import java.util.concurrent.TimeUnit;

public class ClaimsAwareJwkProvider extends GuavaCachedJwkProvider {

  private final String issuer;

  private final String audience;

  public ClaimsAwareJwkProvider(JwkProvider provider, long size, long expiresIn,
      TimeUnit expiresUnit, String issuer, String audience) {
    super(provider, size, expiresIn, expiresUnit);
    this.issuer = issuer;
    this.audience = audience;
  }

  public String getIssuer() {
    return issuer;
  }

  public String getAudience() {
    return audience;
  }
}
