package uk.gov.defra.tracesx.common.security.jwks;

import com.auth0.jwk.UrlJwkProvider;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwkProviderFactory {

  @Value("${spring.security.jwt.maxKeys ?: 5}")
  private int maxCachedKeysPerProvider;

  @Value("${spring.security.jwt.keyExpiryMinutes ?: 60}")
  private int keyExpiryMinutes;

  public ClaimsAwareJwkProvider newInstance(JwksConfiguration config) {
    UrlJwkProvider urlJwkProvider = new UrlJwkProvider(config.getJwksUrl());
    return new ClaimsAwareJwkProvider(
        urlJwkProvider,
        maxCachedKeysPerProvider,
        keyExpiryMinutes,
        TimeUnit.MINUTES,
        config.getIssuer(),
        config.getAudience());
  }
}
