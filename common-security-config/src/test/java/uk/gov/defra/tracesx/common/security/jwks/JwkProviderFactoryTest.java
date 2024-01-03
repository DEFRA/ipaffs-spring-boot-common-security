package uk.gov.defra.tracesx.common.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.MalformedURLException;
import java.net.URL;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.Test;

class JwkProviderFactoryTest {

  private static final URL JWKS_URL;
  static {
    try {
    JWKS_URL = new URL("http://localhost/common/jwks");
    } catch (MalformedURLException e) {
      throw new RuntimeException(e);
    }
  }
  private static final String AUDIENCE = "6f7733c3-ffa9-4e85-8f5e-a9c5814ee3cb";
  private static final String ISSUER = "http://localhost/";

  @Test
  void newInstance_instanceCreateWithInjectedParameters() throws Exception {
    JwkProviderFactory jwkProviderFactory = new JwkProviderFactory();
    JwksConfiguration jwksConfiguration = new JwksConfiguration(JWKS_URL, AUDIENCE, ISSUER);
    FieldUtils.writeField(jwkProviderFactory, "maxCachedKeysPerProvider", 2, true);
    FieldUtils.writeField(jwkProviderFactory, "keyExpiryMinutes", 45, true);
    ClaimsAwareJwkProvider jwkProvider = jwkProviderFactory.newInstance(jwksConfiguration);
    assertThat(jwkProvider.getAudience()).isEqualTo(AUDIENCE);
    assertThat(jwkProvider.getIssuer()).isEqualTo(ISSUER);
  }

}
