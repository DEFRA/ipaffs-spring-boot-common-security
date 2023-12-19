package uk.gov.defra.tracesx.common.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.auth0.jwk.InvalidPublicKeyException;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.defra.tracesx.common.exceptions.InsSecurityException;

@ExtendWith(MockitoExtension.class)
class JwksCacheTest {

  private static final String KID1 = "2d792919-3a36-4edd-9736-edd43b157067";
  private static final String AUD1 = "157f8269-0ca3-435e-83d3-407bfdfd7bb4";
  private static final String ISS1 = "http://first-cert-issuer.com";

  private static final String KID2 = "ed7fd587-bcf8-483d-9d8b-9b5d953cdae5";
  private static final String AUD2 = "d75ab74a-4751-4e8c-8ed0-2c54dd40bf4a";
  private static final String ISS2 = "http://first-cert-issuer.com";

  @Mock
  private JwkProviderFactory jwkProviderFactory;

  @Mock
  private Jwk jwk;

  @Mock
  private PublicKey publicKey;

  @Mock
  private ClaimsAwareJwkProvider jwkProvider1;

  @Mock
  private ClaimsAwareJwkProvider jwkProvider2;

  private JwksCache jwksCache;

  @BeforeEach
  public void setUp() {
    when(jwkProvider1.getIssuer()).thenReturn(ISS1);
    List<JwksConfiguration> configurationList =
        Arrays.asList(
            JwksConfiguration.builder().build(),
            JwksConfiguration.builder().build());
    when(jwkProviderFactory.newInstance(any()))
        .thenReturn(jwkProvider1)
        .thenReturn(jwkProvider2);
    jwksCache = new JwksCache(configurationList, jwkProviderFactory);
  }

  @AfterEach
  public void tearDown() {
    verify(jwkProviderFactory, times(2)).newInstance(any());
    verifyNoMoreInteractions(jwkProvider1, jwkProvider2);
  }

  @Test
  void getPublicKey_keyFoundAfterProviderScan_returnsKeyAndClaims() throws Exception {
    when(jwkProvider2.getAudience()).thenReturn(AUD2);
    when(jwkProvider2.getIssuer()).thenReturn(ISS2);
    when(jwkProvider1.get(anyString())).thenThrow(new JwkException("not found"));
    when(jwk.getPublicKey()).thenReturn(publicKey);
    when(jwkProvider2.get(anyString())).thenReturn(jwk);
    List<KeyAndClaims> keyAndClaims = jwksCache.getPublicKeys(KID2);
    KeyAndClaims keyAndClaim = keyAndClaims.get(0);
    assertThat(keyAndClaim.getKey()).isEqualTo(publicKey);
    assertThat(keyAndClaim.getAud()).isEqualTo(AUD2);
    assertThat(keyAndClaim.getIss()).isEqualTo(ISS2);
    verify(jwkProvider1).get(KID2);
    verify(jwkProvider1).getIssuer(); // logging
    verify(jwkProvider2, times(2)).get(KID2);
    verify(jwkProvider2).getIssuer();
    verify(jwkProvider2).getAudience();
  }

  @Test
  void getPublicKey_keyFoundInCachedProvider_returnsKeyAndClaims() throws Exception {
    when(jwkProvider1.getAudience()).thenReturn(AUD1);
    when(jwkProvider2.getAudience()).thenReturn(AUD2);
    when(jwkProvider2.getIssuer()).thenReturn(ISS2);
    when(jwk.getPublicKey()).thenReturn(publicKey);
    when(jwkProvider1.get(anyString())).thenReturn(jwk);
    when(jwkProvider2.get(anyString())).thenReturn(jwk);
    List<KeyAndClaims> keyAndClaims = jwksCache.getPublicKeys(KID1);
    KeyAndClaims keyAndClaim = keyAndClaims.get(0);
    assertThat(keyAndClaim.getKey()).isEqualTo(publicKey);
    assertThat(keyAndClaim.getAud()).isEqualTo(AUD1);
    assertThat(keyAndClaim.getIss()).isEqualTo(ISS1);
    verify(jwkProvider1, times(2)).get(KID1);
    verify(jwkProvider2, times(2)).get(KID1);

    // on second invocation the provider is only called one more time (no scan)
    keyAndClaim = jwksCache.getPublicKeys(KID1).get(0);
    assertThat(keyAndClaim.getKey()).isEqualTo(publicKey);
    assertThat(keyAndClaim.getAud()).isEqualTo(AUD1);
    assertThat(keyAndClaim.getIss()).isEqualTo(ISS1);
    verify(jwkProvider1, times(3)).get(KID1);
    verify(jwkProvider1, times(2)).getAudience();
    verify(jwkProvider1, times(2)).getIssuer();

    verify(jwkProvider2, times(3)).get(KID1);
    verify(jwkProvider2, times(2)).getAudience();
    verify(jwkProvider2, times(2)).getIssuer();
  }

  @Test
  void getPublicKey__keyFoundAfterProviderScan_sameKidDifferentAUDs() throws JwkException {
    when(jwkProvider1.getAudience()).thenReturn(AUD1);
    when(jwkProvider2.getAudience()).thenReturn(AUD2);
    when(jwkProvider2.getIssuer()).thenReturn(ISS2);
    when(jwkProvider1.get(anyString())).thenReturn(jwk);
    when(jwkProvider2.get(anyString())).thenReturn(jwk);
    when(jwk.getPublicKey()).thenReturn(publicKey);
    List<KeyAndClaims> keyAndClaims = jwksCache.getPublicKeys(KID1);
    KeyAndClaims keyAndClaim = keyAndClaims.get(0);
    assertThat(keyAndClaim.getKey()).isEqualTo(publicKey);
    assertThat(keyAndClaim.getAud()).isEqualTo(AUD1);
    assertThat(keyAndClaim.getIss()).isEqualTo(ISS2);
    keyAndClaim = keyAndClaims.get(1);
    assertThat(keyAndClaim.getKey()).isEqualTo(publicKey);
    assertThat(keyAndClaim.getAud()).isEqualTo(AUD2);
    assertThat(keyAndClaim.getIss()).isEqualTo(ISS2);
    verify(jwkProvider1, times(2)).get(KID1);
    verify(jwkProvider2, times(2)).get(KID1);

    verify(jwkProvider1).getIssuer(); // logging
    verify(jwkProvider2).getIssuer();
    verify(jwkProvider1).getAudience();
    verify(jwkProvider2).getAudience();
  }

  @Test
  void getPublicKey_keyNotFound_throwsException() throws Exception {
    when(jwkProvider1.get(anyString())).thenThrow(new JwkException("not found"));
    when(jwkProvider2.get(anyString())).thenThrow(new JwkException("not found"));
    assertThatExceptionOfType(InsSecurityException.class).isThrownBy(
        () -> jwksCache.getPublicKeys(KID2));
    verify(jwkProvider1).get(KID2);
    verify(jwkProvider2).get(KID2);
    verify(jwkProvider1).getIssuer(); // logging
    verify(jwkProvider2).getIssuer(); // logging
  }

  @Test
  void getPublicKey_invalidSecurityException() throws JwkException {
    when(jwk.getPublicKey()).thenThrow(
        new InvalidPublicKeyException("Exception from unit test", new Throwable()));
    when(jwkProvider1.get(anyString())).thenReturn(jwk);
    assertThatExceptionOfType(InsSecurityException.class)
        .isThrownBy(() -> jwksCache.getPublicKeys(KID1));

    verify(jwkProvider1, times(2)).get(KID1);
    verify(jwkProvider2).get(KID1);
    verify(jwkProvider1, times(1)).getAudience();
    verify(jwkProvider1, times(1)).getIssuer();
  }
}
