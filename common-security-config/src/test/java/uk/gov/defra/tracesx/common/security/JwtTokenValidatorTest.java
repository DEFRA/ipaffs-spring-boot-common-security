package uk.gov.defra.tracesx.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.KeyPair;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import uk.gov.defra.tracesx.common.exceptions.UnauthorizedException;
import uk.gov.defra.tracesx.common.security.jwks.JwksCache;
import uk.gov.defra.tracesx.common.security.jwks.KeyAndClaims;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;
import uk.gov.defra.tracesx.common.security.jwt.JwtUserMapper;

@RunWith(MockitoJUnitRunner.class)
public class JwtTokenValidatorTest {

  private static final KeyPair KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);
  private static final KeyPair ALT_KEY_PAIR = Keys.keyPairFor(SignatureAlgorithm.RS256);
  private static final String KID = "2759cfa1-6096-4779-b888-983e94e3f6b3";
  private static final String ISS = "http://issuer.com";
  private static final String AUD = "279fb646-b442-4ac0-b42a-1912a4ec5e65";
  @Mock
  private JwtUserMapper jwtUserMapper;

  @Mock
  private JwksCache jwksCache;

  @Mock
  private IdTokenUserDetails expectedUserDetails;

  private JwtTokenValidator jwtTokenValidator;

  private List<KeyAndClaims> keyAndClaims = Arrays.asList(KeyAndClaims.builder()
      .key(KEY_PAIR.getPublic())
      .aud(AUD)
      .iss(ISS)
      .build());

  @Before
  public void setUp() {
    this.jwtTokenValidator = new JwtTokenValidator(jwtUserMapper, jwksCache, new ObjectMapper());
  }

  @After
  public void tearDown() {
    verifyNoMoreInteractions(jwksCache, jwtUserMapper);
  }

  @Test
  public void validateToken_valid_successfully() throws UnauthorizedException {
    Date exp = Date.from(LocalDateTime.now().plusDays(1).toInstant(ZoneOffset.UTC));
    String token =
        Jwts.builder().setHeader(Collections.singletonMap("kid", KID))
            .setExpiration(exp)
            .claim("aud", AUD)
            .claim("iss", ISS)
            .signWith(KEY_PAIR.getPrivate()).compact();
    when(jwksCache.getPublicKeys(KID)).thenReturn(keyAndClaims);
    when(jwtUserMapper.createUser(any(), eq(token))).thenReturn(expectedUserDetails);
    IdTokenUserDetails userDetails = jwtTokenValidator.validateToken(token);
    assertThat(userDetails).isEqualTo(expectedUserDetails);
    verify(jwksCache).getPublicKeys(KID);
    verify(jwtUserMapper).createUser(any(), eq(token));
  }

  @Test
  public void validateToken_withoutKid_throwsException() {
    String token =
        Jwts.builder().setHeader(Collections.emptyMap())
            .claim("oid", "ac4cc24d-5351-49ee-83e6-1ddaab285524")
            .signWith(KEY_PAIR.getPrivate()).compact();
    assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> jwtTokenValidator.validateToken(token));
  }

  @Test
  public void validateToken_expired_throwsException() {
    Date exp = Date.from(LocalDateTime.now().minusDays(1).toInstant(ZoneOffset.UTC));
    String token =
        Jwts.builder().setHeader(Collections.singletonMap("kid", KID))
            .setExpiration(exp)
            .claim("aud", AUD)
            .claim("iss", ISS)
            .signWith(KEY_PAIR.getPrivate()).compact();
    when(jwksCache.getPublicKeys(KID)).thenReturn(keyAndClaims);
    assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> jwtTokenValidator.validateToken(token));
    verify(jwksCache).getPublicKeys(KID);
  }

  @Test
  public void validateToken_missingExpiry_throwsException() {
    String token =
        Jwts.builder().setHeader(Collections.singletonMap("kid", KID))
            .claim("aud", AUD)
            .claim("iss", ISS)
            .signWith(KEY_PAIR.getPrivate()).compact();
    when(jwksCache.getPublicKeys(KID)).thenReturn(keyAndClaims);
    assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> jwtTokenValidator.validateToken(token));
    verify(jwksCache).getPublicKeys(KID);
  }

  @Test
  public void validateToken_expiryInvalidFormat_throwsException() {
    String token =
        Jwts.builder().setHeader(Collections.singletonMap("kid", KID))
            .claim("exp", new Date().toString())
            .claim("aud", AUD)
            .claim("iss", ISS)
            .signWith(KEY_PAIR.getPrivate()).compact();
    when(jwksCache.getPublicKeys(KID)).thenReturn(keyAndClaims);
    assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> jwtTokenValidator.validateToken(token));
    verify(jwksCache).getPublicKeys(KID);
  }

  @Test
  public void validateToken_invalidSignature_throwsException() {
    Date exp = Date.from(LocalDateTime.now().plusDays(1).toInstant(ZoneOffset.UTC));
    String token =
        Jwts.builder().setHeader(Collections.singletonMap("kid", KID))
            .setExpiration(exp)
            .claim("aud", AUD)
            .claim("iss", ISS)
            .signWith(ALT_KEY_PAIR.getPrivate()).compact();
    when(jwksCache.getPublicKeys(KID)).thenReturn(keyAndClaims);
    assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> jwtTokenValidator.validateToken(token));
    verify(jwksCache).getPublicKeys(KID);
  }

  @Test
  public void validateToken_invalidAudience_throwsException() {
    Date exp = Date.from(LocalDateTime.now().plusDays(1).toInstant(ZoneOffset.UTC));
    String token =
        Jwts.builder().setHeader(Collections.singletonMap("kid", KID))
            .setExpiration(exp)
            .claim("aud", "invalid_audience")
            .claim("iss", ISS)
            .signWith(KEY_PAIR.getPrivate()).compact();
    when(jwksCache.getPublicKeys(KID)).thenReturn(keyAndClaims);
    assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> jwtTokenValidator.validateToken(token));
    verify(jwksCache).getPublicKeys(KID);
  }

  @Test
  public void validateToken_invalidIssuer_throwsException() {
    Date exp = Date.from(LocalDateTime.now().plusDays(1).toInstant(ZoneOffset.UTC));
    String token =
        Jwts.builder().setHeader(Collections.singletonMap("kid", KID))
            .setExpiration(exp)
            .claim("aud", AUD)
            .claim("iss", "invalid_issuer")
            .signWith(KEY_PAIR.getPrivate()).compact();
    when(jwksCache.getPublicKeys(KID)).thenReturn(keyAndClaims);
    assertThatExceptionOfType(UnauthorizedException.class)
        .isThrownBy(() -> jwtTokenValidator.validateToken(token));
    verify(jwksCache).getPublicKeys(KID);
  }

}
