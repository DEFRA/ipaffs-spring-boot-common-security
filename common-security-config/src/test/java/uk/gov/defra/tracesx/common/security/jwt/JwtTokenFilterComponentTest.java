package uk.gov.defra.tracesx.common.security.jwt;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
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
import static uk.gov.defra.tracesx.common.security.jwt.MockJwks.createToken1;

import com.auth0.jwk.JwkProvider;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URL;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import uk.gov.defra.tracesx.common.security.RoleToAuthorityMapper;
import uk.gov.defra.tracesx.common.security.jwks.JwkProviderFactory;
import uk.gov.defra.tracesx.common.security.jwks.JwksCache;
import uk.gov.defra.tracesx.common.security.jwks.JwksConfiguration;

public class JwtTokenFilterComponentTest {

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
  private FilterChain filterChain;
  private JwkProvider jwkProvider;

  @Before
  public void before() throws Exception {
    roleToAuthorityMapper = new RoleToAuthorityMapper();
    jwtUserMapper = new JwtUserMapper(roleToAuthorityMapper);
    jwksConfiguration1 = JwksConfiguration.builder().jwksUrl(new URL(JWKS_URL1)).audience(JWKS_AUDIENCE1).issuer(JWKS_ISSUER1).build();
    jwksConfiguration2 = JwksConfiguration.builder().jwksUrl(new URL(JWKS_URL2)).audience(JWKS_AUDIENCE2).issuer(JWKS_ISSUER2).build();
    jwksConfigurations = Arrays.asList(jwksConfiguration1, jwksConfiguration2);
    jwkProviderFactory = spy(new SpyableJwkProviderFactory());
    FieldUtils.writeField(jwkProviderFactory, "maxCachedKeysPerProvider", 5, true);
    FieldUtils.writeField(jwkProviderFactory, "keyExpiryMinutes", 250, true); // millis
    FieldUtils.writeField(jwkProviderFactory, "keyExpiryUnits", TimeUnit.MILLISECONDS, true);
    jwkProvider = mock(JwkProvider.class);
    when(jwkProvider.get(JWK_ELEMENT1.getKid())).thenReturn(JWK1);
    when(jwkProvider.get(JWK_ELEMENT2.getKid())).thenReturn(JWK2);
    doReturn(jwkProvider).when(jwkProviderFactory).createUrlJwkProvider(any(URL.class));
    jwksCache = spy(new JwksCache(jwksConfigurations, jwkProviderFactory));
    jwtTokenValidator = new JwtTokenValidator(jwtUserMapper, jwksCache, objectMapper);
    jwtTokenFilter = new JwtTokenFilter(jwtTokenValidator);

    request = mock(HttpServletRequest.class);
    response = mock(HttpServletResponse.class);
    filterChain = mock(FilterChain.class);
  }

  @After
  public void after() {
    verifyNoMoreInteractions(filterChain, response, jwkProvider, jwksCache);
  }

  @Test
  public void doFilter_validRequest_succeeds() throws Exception {
    when(request.getHeader("Authorization")).thenReturn("Bearer " + createToken1(expiresInTenMinutes()));
    jwtTokenFilter.doFilterInternal(request, response, filterChain);
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // TODO: assert
    verify(filterChain).doFilter(request, response);
    verify(jwksCache).getPublicKeys(JWK_ELEMENT1.getKid());
    verify(jwkProvider).get(JWK_ELEMENT1.getKid());
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
