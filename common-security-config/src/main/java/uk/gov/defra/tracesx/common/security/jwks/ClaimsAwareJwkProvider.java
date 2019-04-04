package uk.gov.defra.tracesx.common.security.jwks;

import com.auth0.jwk.GuavaCachedJwkProvider;
import com.auth0.jwk.JwkProvider;
import java.util.concurrent.TimeUnit;

/**
 * Extends {@link GuavaCachedJwkProvider} to add issuer and audience properties. IPAFFS supports
 * multiple authentication providers differentiated by their issuer and audience claims. These
 * properties allow the correct provider to be picked based on the claims.
 */
public class ClaimsAwareJwkProvider extends GuavaCachedJwkProvider {

  private final String issuer;

  private final String audience;

  /**
   * Creates a new cached provider specifying cache size and ttl
   *
   * @param provider fallback provider to use when jwk is not cached
   * @param size number of jwt to cache
   * @param expiresIn amount of time a jwk will live in the cache
   * @param expiresUnit unit of the expiresIn parameter
   * @param issuer the issuer associated with this jwk provider
   * @param audience the audience associated with this jwk provider
   */
  public ClaimsAwareJwkProvider(
      JwkProvider provider,
      long size,
      long expiresIn,
      TimeUnit expiresUnit,
      String issuer,
      String audience) {
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
