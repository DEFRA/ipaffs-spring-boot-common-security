package uk.gov.defra.tracesx.common.security.jwks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import java.util.concurrent.TimeUnit;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class ClaimsAwareJwkProviderTest {

  private static final String ISSUER = "http://issuer.com/";
  private static final String AUDIENCE = "ec00835d-a3a2-42c8-b849-9b4cbf7bf92c";
  private static final String KEY_ID = "OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk";

  @Mock
  private JwkProvider jwkProvider;

  @Mock Jwk jwk;

  private ClaimsAwareJwkProvider claimsAwareJwkProvider;

  @Before
  public void before() throws Exception {
    claimsAwareJwkProvider = new ClaimsAwareJwkProvider(jwkProvider, 5, 500, TimeUnit.MILLISECONDS, ISSUER, AUDIENCE);
    when(jwkProvider.get(KEY_ID)).thenReturn(jwk);
  }

  @Test
  public void get_calledOnce_keyIsFetched() throws Exception {
    Jwk result = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    assertThat(result).isSameAs(jwk);
    verify(jwkProvider).get(KEY_ID);
  }

  @Test
  public void get_calledTwice_keyIsFetchedOnce() throws Exception {
    Jwk result1 = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    Jwk result2 = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    assertThat(result1).isSameAs(jwk);
    assertThat(result2).isSameAs(jwk);
    verify(jwkProvider).get(KEY_ID);
  }

  @Test
  public void get_calledTwiceAfterExpiresIn_keyIsFetchedTwice() throws Exception {
    Jwk result1 = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    Thread.sleep(750);
    Jwk result2 = claimsAwareJwkProvider.get("OGZiYTNmNGUtYTM5Zi00NGRhLTgxYjYtMDNiNDc0MDAzMDBk");
    assertThat(result1).isSameAs(jwk);
    assertThat(result2).isSameAs(jwk);
    verify(jwkProvider, times(2)).get(KEY_ID);
  }

  @Test
  public void getIssuer_returnsIssuer() {
    assertThat(claimsAwareJwkProvider.getIssuer()).isEqualTo(ISSUER);
  }

  @Test
  public void getAudience_returnsAudience() {
    assertThat(claimsAwareJwkProvider.getAudience()).isEqualTo(AUDIENCE);
  }

}
