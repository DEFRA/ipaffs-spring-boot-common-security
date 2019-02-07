package uk.gov.defra.tracesx.common.security.jwks;

import com.auth0.jwk.UrlJwkProvider;
import java.util.concurrent.TimeUnit;
import org.springframework.stereotype.Component;

@Component
public class JwkProviderFactory {

  private static final int MAX_CACHED_KEYS_PER_PROVIDER = 5;
  private static final int KEY_CACHE_EXPIRY_MINUTES = 30;

  public ClaimsAwareJwkProvider newInstance(JwksConfiguration config) {
    UrlJwkProvider urlJwkProvider = new UrlJwkProvider(config.getJwksUrl());
    return new ClaimsAwareJwkProvider(
        urlJwkProvider,
        MAX_CACHED_KEYS_PER_PROVIDER,
        KEY_CACHE_EXPIRY_MINUTES,
        TimeUnit.MINUTES,
        config.getIssuer(),
        config.getAudience());
  }

}
