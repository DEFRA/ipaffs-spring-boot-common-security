package uk.gov.defra.tracesx.common.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import java.time.Duration;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ClaimsAwareJwkProviderTest {

  private static final String ISSUER = "http://issuer.com/";
  private static final String AUDIENCE = "ec00835d-a3a2-42c8-b849-9b4cbf7bf92c";
  private static final String KEY_ID = "OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk";
  @Mock
  Jwk jwk;
  @Mock
  private JwkProvider jwkProvider;
  private ClaimsAwareJwkProvider claimsAwareJwkProvider;

  @BeforeEach
  public void before() {
    claimsAwareJwkProvider = new ClaimsAwareJwkProvider(jwkProvider, 5, 500, TimeUnit.MILLISECONDS,
        ISSUER, AUDIENCE);
  }

  @Test
  void get_calledOnce_keyIsFetched() throws Exception {
    when(jwkProvider.get(KEY_ID)).thenReturn(jwk);
    Jwk result = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    assertThat(result).isSameAs(jwk);
    verify(jwkProvider).get(KEY_ID);
  }

  @Test
  void get_calledTwice_keyIsFetchedOnce() throws Exception {
    when(jwkProvider.get(KEY_ID)).thenReturn(jwk);
    Jwk result1 = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    Jwk result2 = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    assertThat(result1).isSameAs(jwk);
    assertThat(result2).isSameAs(jwk);
    verify(jwkProvider).get(KEY_ID);
  }

  @Test
  void get_calledTwiceAfterExpiresIn_keyIsFetchedTwice() throws Exception {
    when(jwkProvider.get(KEY_ID)).thenReturn(jwk);
    Jwk result1 = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    await().pollDelay(Duration.ofMillis(750)).until(() -> true);
    Jwk result2 = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    assertThat(result1).isSameAs(jwk);
    assertThat(result2).isSameAs(jwk);
    verify(jwkProvider, times(2)).get(KEY_ID);
  }

  @Test
  void getIssuer_returnsIssuer() {
    assertThat(claimsAwareJwkProvider.getIssuer()).isEqualTo(ISSUER);
  }

  @Test
  void getAudience_returnsAudience() {
    assertThat(claimsAwareJwkProvider.getAudience()).isEqualTo(AUDIENCE);
  }
}
