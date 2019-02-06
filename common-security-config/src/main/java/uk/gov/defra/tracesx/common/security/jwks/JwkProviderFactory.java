package uk.gov.defra.tracesx.common.security.jwks;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import java.net.URL;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwkProviderFactory {

  @Value("${spring.security.jwt.maxKeys ?: 5}")
  private int maxCachedKeysPerProvider;

  @Value("${spring.security.jwt.keyExpiryMinutes ?: 60}")
  private int keyExpiryMinutes;

  private TimeUnit keyExpiryUnits = TimeUnit.MINUTES;

  public ClaimsAwareJwkProvider newInstance(JwksConfiguration config) {
    JwkProvider urlJwkProvider = createUrlJwkProvider(config.getJwksUrl());
    return new ClaimsAwareJwkProvider(
        urlJwkProvider,
        maxCachedKeysPerProvider,
        keyExpiryMinutes,
        keyExpiryUnits,
        config.getIssuer(),
        config.getAudience());
  }

  protected JwkProvider createUrlJwkProvider(URL url) {
    return new UrlJwkProvider(url);
  }

}
