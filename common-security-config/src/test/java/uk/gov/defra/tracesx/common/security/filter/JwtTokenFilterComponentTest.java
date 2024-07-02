package uk.gov.defra.tracesx.common.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.CENTRAL_COMPETENT_AUTHORITY;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.FAMILY_NAME;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.GIVEN_NAME;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWK1;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWK2;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWKS_AUDIENCE1;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWKS_AUDIENCE2;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWKS_ISSUER1;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWKS_ISSUER2;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWKS_URL1;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWKS_URL2;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWK_ELEMENT1;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.JWK_ELEMENT2;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.SUB_VALUE;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.createToken1;
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.createToken2;

import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.SigningKeyNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URL;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import uk.gov.defra.tracesx.common.security.IdTokenAuthentication;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.OrganisationGrantedAuthority;
import uk.gov.defra.tracesx.common.security.RoleToAuthorityMapper;
import uk.gov.defra.tracesx.common.security.jwks.JwkProviderFactory;
import uk.gov.defra.tracesx.common.security.jwks.JwksCache;
import uk.gov.defra.tracesx.common.security.jwks.JwksConfiguration;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;
import uk.gov.defra.tracesx.common.security.jwt.JwtUserMapper;
import uk.gov.defra.tracesx.common.security.jwt.MockJwks;

class JwtTokenFilterComponentTest {

  private static final int KEY_EXPIRY_MILLIS = 250;

  private JwtTokenFilter jwtTokenFilter;
  private JwksCache jwksCache;
  private SpyableJwkProviderFactory jwkProviderFactory;

  private HttpServletRequest request;
  private HttpServletResponse response;
  private JwkProvider jwkProvider1;
  private JwkProvider jwkProvider2;

  @BeforeEach
  public void before() throws Exception {
    RoleToAuthorityMapper roleToAuthorityMapper = new RoleToAuthorityMapper();
    JwtUserMapper jwtUserMapper = new JwtUserMapper(roleToAuthorityMapper);

    JwksConfiguration jwksConfiguration1 = JwksConfiguration.builder().jwksUrl(new URL(JWKS_URL1))
        .audience(JWKS_AUDIENCE1).issuer(JWKS_ISSUER1).build();
    JwksConfiguration jwksConfiguration2 = JwksConfiguration.builder().jwksUrl(new URL(JWKS_URL2))
        .audience(JWKS_AUDIENCE2).issuer(JWKS_ISSUER2).build();
    List<JwksConfiguration> jwksConfigurations = Arrays.asList(jwksConfiguration1,
        jwksConfiguration2);

    // expire the key in milliseconds instead of seconds
    jwkProviderFactory = spy(new SpyableJwkProviderFactory());
    FieldUtils.writeField(jwkProviderFactory, "maxCachedKeysPerProvider", 5, true);
    FieldUtils
        .writeField(jwkProviderFactory, "keyExpiryMinutes", KEY_EXPIRY_MILLIS, true); // millis
    FieldUtils.writeField(jwkProviderFactory, "keyExpiryUnits", TimeUnit.MILLISECONDS, true);

    // providers should return the jwk for their respective kids else throw a not found exception
    jwkProvider1 = mock(JwkProvider.class, "jwkProvider1");
    when(jwkProvider1.get(JWK_ELEMENT1.getKid())).thenReturn(JWK1);
    when(jwkProvider1.get(not(eq(JWK_ELEMENT1.getKid()))))
        .thenThrow(new SigningKeyNotFoundException("not found", null));
    jwkProvider2 = mock(JwkProvider.class, "jwkProvider2");
    when(jwkProvider2.get(JWK_ELEMENT2.getKid())).thenReturn(JWK2);
    when(jwkProvider2.get(not(eq(JWK_ELEMENT2.getKid()))))
        .thenThrow(new SigningKeyNotFoundException("not found", null));
    // return the correct mock for the jwk url
    doReturn(jwkProvider1).when(jwkProviderFactory).createUrlJwkProvider(new URL(JWKS_URL1));
    doReturn(jwkProvider2).when(jwkProviderFactory).createUrlJwkProvider(new URL(JWKS_URL2));

    jwksCache = spy(new JwksCache(jwksConfigurations, jwkProviderFactory));
    JwtTokenValidator jwtTokenValidator = new JwtTokenValidator(jwtUserMapper, jwksCache);
    jwtTokenFilter = new JwtTokenFilter("/url", jwtTokenValidator);

    request = mock(HttpServletRequest.class);
    response = mock(HttpServletResponse.class);
  }

  @AfterEach
  public void after() {
    verifyNoMoreInteractions(response, jwkProvider1, jwkProvider2, jwksCache, jwkProviderFactory);
  }

  @Test
  void doFilter_validRequestsSingleProvider_eachProviderIsCalledOnce() throws Exception {
    when(request.getHeader("Authorization"))
        .thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    Authentication authentication;

    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication, true);
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication, true);
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication, true);

    verify(jwkProviderFactory, times(2)).newInstance(any(JwksConfiguration.class));
    verify(jwkProviderFactory).createUrlJwkProvider(new URL(JWKS_URL1));
    verify(jwkProviderFactory).createUrlJwkProvider(new URL(JWKS_URL2));

    verify(jwkProvider1).get(JWK_ELEMENT1.getKid());
    verify(jwkProvider2).get(JWK_ELEMENT1.getKid());

    verify(jwksCache, times(3)).getPublicKeys(JWK_ELEMENT1.getKid());
  }

  private static final List<GrantedAuthority> EXPECTED_AUTHORITIES = MockJwks.ROLES_VALUE.stream()
      .<GrantedAuthority>map(OrganisationGrantedAuthority::new)
      .toList();

  private void assertThatAuthenticationIsValid(Authentication authentication, boolean ccaRequired) {
    assertThat(authentication).isInstanceOf(IdTokenAuthentication.class);
    assertThat(authentication.isAuthenticated()).isTrue();
    assertThat(authentication.getAuthorities()).isEqualTo(EXPECTED_AUTHORITIES);
    assertThat(authentication.getPrincipal()).isEqualTo(SUB_VALUE);
    assertThat(authentication.getDetails()).isInstanceOf(IdTokenUserDetails.class);
    IdTokenUserDetails details = (IdTokenUserDetails) authentication.getDetails();
    assertThat(details.getUserObjectId()).isEqualTo(SUB_VALUE);
    assertThat(details.getDisplayName()).isEqualTo(GIVEN_NAME + " " + FAMILY_NAME);
    assertThat(details.getUsername()).isEqualTo(SUB_VALUE);
    assertThat(details.getPassword()).isNull();
    assertThat(details.getAuthorities()).isEqualTo(EXPECTED_AUTHORITIES);
    assertThat(details.getIdToken()).isNotBlank();
    if (ccaRequired) {
      assertThat(details.getCentralCompetentAuthority()).isEqualTo(CENTRAL_COMPETENT_AUTHORITY);
    } else {
      assertThat(details.getCentralCompetentAuthority()).isNull();
    }
  }

  @Test
  void doFilter_validRequestsMultipleProviders_eachProviderIsCalledOnce() throws Exception {
    Authentication authentication;
    when(request.getHeader("Authorization"))
        .thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication, true);

    when(request.getHeader("Authorization"))
        .thenReturn("Bearer " + createToken2(expiresInTenMinutes()));
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication, false);

    when(request.getHeader("Authorization"))
        .thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication, true);

    verify(jwkProviderFactory, times(2)).newInstance(any(JwksConfiguration.class));
    verify(jwkProviderFactory).createUrlJwkProvider(new URL(JWKS_URL1));
    verify(jwkProviderFactory).createUrlJwkProvider(new URL(JWKS_URL2));

    verify(jwkProvider1).get(JWK_ELEMENT1.getKid());
    verify(jwkProvider2).get(JWK_ELEMENT1.getKid());
    verify(jwkProvider1).get(JWK_ELEMENT2.getKid());
    verify(jwkProvider2).get(JWK_ELEMENT2.getKid());

    verify(jwksCache, times(2)).getPublicKeys(JWK_ELEMENT1.getKid());
    verify(jwksCache).getPublicKeys(JWK_ELEMENT2.getKid());
  }

  @Test
  void doFilter_keyExpiresBetweenRequests_keyIsFetchedAgain() throws Exception {
    when(request.getHeader("Authorization"))
        .thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    Authentication authentication;

    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication, true);

    await().pollDelay(Duration.ofMillis(KEY_EXPIRY_MILLIS * 2)).until(() -> true);

    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication, true);

    verify(jwkProviderFactory, times(2)).newInstance(any(JwksConfiguration.class));
    verify(jwkProviderFactory).createUrlJwkProvider(new URL(JWKS_URL1));
    verify(jwkProviderFactory).createUrlJwkProvider(new URL(JWKS_URL2));

    verify(jwkProvider1, times(2)).get(JWK_ELEMENT1.getKid());
    verify(jwkProvider2).get(JWK_ELEMENT1.getKid());

    verify(jwksCache, times(2)).getPublicKeys(JWK_ELEMENT1.getKid());
  }

  private Date expiresInTenMinutes() {
    return Date.from(OffsetDateTime.now(ZoneId.of("UTC")).plusMinutes(10).toInstant());
  }

  static class SpyableJwkProviderFactory extends JwkProviderFactory {

    @Override
    protected JwkProvider createUrlJwkProvider(URL url) {
      return super.createUrlJwkProvider(url);
    }
  }

}
