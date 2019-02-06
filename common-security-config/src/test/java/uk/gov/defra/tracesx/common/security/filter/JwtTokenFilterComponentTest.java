package uk.gov.defra.tracesx.common.security.filter;

import static org.assertj.core.api.Assertions.assertThat;
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
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URL;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import uk.gov.defra.tracesx.common.security.IdTokenAuthentication;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.RoleToAuthorityMapper;
import uk.gov.defra.tracesx.common.security.jwks.JwkProviderFactory;
import uk.gov.defra.tracesx.common.security.jwks.JwksCache;
import uk.gov.defra.tracesx.common.security.jwks.JwksConfiguration;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;
import uk.gov.defra.tracesx.common.security.jwt.JwtUserMapper;
import uk.gov.defra.tracesx.common.security.jwt.MockJwks;

public class JwtTokenFilterComponentTest {

  private static final int KEY_EXPIRY_MILLIS = 250;

  private JwtTokenFilter jwtTokenFilter;
  private JwtTokenValidator jwtTokenValidator;
  private JwtUserMapper jwtUserMapper;
  private RoleToAuthorityMapper roleToAuthorityMapper;
  private JwksCache jwksCache;
  private List<JwksConfiguration> jwksConfigurations;
  private SpyableJwkProviderFactory jwkProviderFactory;
  private ObjectMapper objectMapper = new ObjectMapper();

  private JwksConfiguration jwksConfiguration1;
  private JwksConfiguration jwksConfiguration2;

  private HttpServletRequest request;
  private HttpServletResponse response;
  private JwkProvider jwkProvider1;
  private JwkProvider jwkProvider2;

  @Before
  public void before() throws Exception {
    roleToAuthorityMapper = new RoleToAuthorityMapper();
    jwtUserMapper = new JwtUserMapper(roleToAuthorityMapper);

    jwksConfiguration1 = JwksConfiguration.builder().jwksUrl(new URL(JWKS_URL1)).audience(JWKS_AUDIENCE1).issuer(JWKS_ISSUER1).build();
    jwksConfiguration2 = JwksConfiguration.builder().jwksUrl(new URL(JWKS_URL2)).audience(JWKS_AUDIENCE2).issuer(JWKS_ISSUER2).build();
    jwksConfigurations = Arrays.asList(jwksConfiguration1, jwksConfiguration2);

    // expire the key in milliseconds instead of seconds
    jwkProviderFactory = spy(new SpyableJwkProviderFactory());
    FieldUtils.writeField(jwkProviderFactory, "maxCachedKeysPerProvider", 5, true);
    FieldUtils.writeField(jwkProviderFactory, "keyExpiryMinutes", KEY_EXPIRY_MILLIS, true); // millis
    FieldUtils.writeField(jwkProviderFactory, "keyExpiryUnits", TimeUnit.MILLISECONDS, true);

    // providers should return the jwk for their respective kids else throw a not found exception
    jwkProvider1 = mock(JwkProvider.class, "jwkProvider1");
    when(jwkProvider1.get(eq(JWK_ELEMENT1.getKid()))).thenReturn(JWK1);
    when(jwkProvider1.get(not(eq(JWK_ELEMENT1.getKid())))).thenThrow(new SigningKeyNotFoundException("not found", null));
    jwkProvider2 = mock(JwkProvider.class, "jwkProvider2");
    when(jwkProvider2.get(JWK_ELEMENT2.getKid())).thenReturn(JWK2);
    when(jwkProvider2.get(not(eq(JWK_ELEMENT2.getKid())))).thenThrow(new SigningKeyNotFoundException("not found", null));
    // return the correct mock for the jwk url
    doReturn(jwkProvider1).when(jwkProviderFactory).createUrlJwkProvider(eq(new URL(JWKS_URL1)));
    doReturn(jwkProvider2).when(jwkProviderFactory).createUrlJwkProvider(eq(new URL(JWKS_URL2)));

    jwksCache = spy(new JwksCache(jwksConfigurations, jwkProviderFactory));
    jwtTokenValidator = new JwtTokenValidator(jwtUserMapper, jwksCache, objectMapper);
    jwtTokenFilter = new JwtTokenFilter("/url", jwtTokenValidator);

    request = mock(HttpServletRequest.class);
    response = mock(HttpServletResponse.class);
  }

  @After
  public void after() {
    verifyNoMoreInteractions(response, jwkProvider1, jwkProvider2, jwksCache, jwkProviderFactory);
  }

  @Test
  public void doFilter_validRequestsSingleProvider_eachProviderIsCalledOnce() throws Exception {
    when(request.getHeader("Authorization")).thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    Authentication authentication;

    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication);
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication);
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication);

    verify(jwkProviderFactory, times(2)).newInstance(any(JwksConfiguration.class));
    verify(jwkProviderFactory).createUrlJwkProvider(eq(new URL(JWKS_URL1)));
    verify(jwkProviderFactory).createUrlJwkProvider(eq(new URL(JWKS_URL2)));

    verify(jwkProvider1).get(JWK_ELEMENT1.getKid());
    verify(jwkProvider2).get(JWK_ELEMENT1.getKid());

    verify(jwksCache, times(3)).getPublicKeys(JWK_ELEMENT1.getKid());
  }

  private static final List<GrantedAuthority> EXPECTED_AUTHORITIES = Collections.unmodifiableList(MockJwks.ROLES_VALUE.stream().map(
      SimpleGrantedAuthority::new).collect(Collectors.toList()));

  private void assertThatAuthenticationIsValid(Authentication authentication) {
    assertThat(authentication).isInstanceOf(IdTokenAuthentication.class);
    assertThat(authentication.isAuthenticated()).isTrue();
    assertThat(authentication.getAuthorities()).containsOnlyElementsOf((Iterable) EXPECTED_AUTHORITIES);
    assertThat(authentication.getPrincipal()).isEqualTo(SUB_VALUE);
    assertThat(authentication.getDetails()).isInstanceOf(IdTokenUserDetails.class);
    IdTokenUserDetails details = (IdTokenUserDetails) authentication.getDetails();
    assertThat(details.getUserObjectId()).isEqualTo(SUB_VALUE);
    assertThat(details.getDisplayName()).isEqualTo(SUB_VALUE);
    assertThat(details.getUsername()).isEqualTo(SUB_VALUE);
    assertThat(details.getPassword()).isNull();
    assertThat(details.getAuthorities()).containsOnlyElementsOf((Iterable) EXPECTED_AUTHORITIES);
    assertThat(details.getIdToken()).isNotBlank();
  }

  @Test
  public void doFilter_validRequestsMultipleProviders_eachProviderIsCalledOnce() throws Exception {
    Authentication authentication;
    when(request.getHeader("Authorization")).thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication);


    when(request.getHeader("Authorization")).thenReturn("Bearer " + createToken2(expiresInTenMinutes()));
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication);

    when(request.getHeader("Authorization")).thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication);

    verify(jwkProviderFactory, times(2)).newInstance(any(JwksConfiguration.class));
    verify(jwkProviderFactory).createUrlJwkProvider(eq(new URL(JWKS_URL1)));
    verify(jwkProviderFactory).createUrlJwkProvider(eq(new URL(JWKS_URL2)));

    verify(jwkProvider1).get(JWK_ELEMENT1.getKid());
    verify(jwkProvider2).get(JWK_ELEMENT1.getKid());
    verify(jwkProvider1).get(JWK_ELEMENT2.getKid());
    verify(jwkProvider2).get(JWK_ELEMENT2.getKid());

    verify(jwksCache, times(2)).getPublicKeys(JWK_ELEMENT1.getKid());
    verify(jwksCache).getPublicKeys(JWK_ELEMENT2.getKid());
  }

  @Test
  public void doFilter_keyExpiresBetweenRequests_keyIsFetchedAgain() throws Exception {
    when(request.getHeader("Authorization")).thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    Authentication authentication;

    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication);

    Thread.sleep(KEY_EXPIRY_MILLIS * 2);

    authentication = jwtTokenFilter.attemptAuthentication(request, response);
    assertThatAuthenticationIsValid(authentication);

    verify(jwkProviderFactory, times(2)).newInstance(any(JwksConfiguration.class));
    verify(jwkProviderFactory).createUrlJwkProvider(eq(new URL(JWKS_URL1)));
    verify(jwkProviderFactory).createUrlJwkProvider(eq(new URL(JWKS_URL2)));

    verify(jwkProvider1, times(2)).get(JWK_ELEMENT1.getKid());
    verify(jwkProvider2).get(JWK_ELEMENT1.getKid());

    verify(jwksCache, times(2)).getPublicKeys(JWK_ELEMENT1.getKid());
  }

  private Date expiresInTenMinutes() {
    return Date.from(OffsetDateTime.now(ZoneId.of("UTC")).plus(10, ChronoUnit.MINUTES).toInstant());
  }

  static class SpyableJwkProviderFactory extends JwkProviderFactory {
    @Override
    protected JwkProvider createUrlJwkProvider(URL url) {
      return super.createUrlJwkProvider(url);
    }
  }

}
