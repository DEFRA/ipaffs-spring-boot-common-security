package uk.gov.defra.tracesx.common.security.jwt;

import static uk.gov.defra.tracesx.common.security.jwt.JwtContants.EXP;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.jwt.crypto.sign.SignatureVerifier;
import org.springframework.stereotype.Component;
import uk.gov.defra.tracesx.common.exceptions.JwtAuthenticationException;
import uk.gov.defra.tracesx.common.security.IdTokenUserDetails;
import uk.gov.defra.tracesx.common.security.jwks.JwksCache;
import uk.gov.defra.tracesx.common.security.jwks.KeyAndClaims;

import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Component
public class JwtTokenValidator {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwtTokenValidator.class);
  private static final String AUD = "aud";
  private static final String ISS = "iss";

  private final JwtUserMapper jwtUserMapper;
  private final JwksCache jwksCache;
  private final ObjectMapper objectMapper;

  public JwtTokenValidator(
      JwtUserMapper jwtUserMapper, JwksCache jwksCache, ObjectMapper objectMapper) {
    this.jwtUserMapper = jwtUserMapper;
    this.jwksCache = jwksCache;
    this.objectMapper = objectMapper;
  }

  public IdTokenUserDetails validateToken(String idToken) {
    Map<String, Object> decoded = decode(idToken);
    return jwtUserMapper.createUser(decoded, idToken);
  }

  private Map<String, Object> decode(String idToken) {
    String kid = JwtHelper.headers(idToken).get("kid");
    if (StringUtils.isEmpty(kid)) {
      LOGGER.error("Key id (kid) is missing from the id token header.");
      throw unauthorizedException();
    }

    List<KeyAndClaims> keyAndClaims = jwksCache.getPublicKeys(kid);
    for (KeyAndClaims keyAndClaim : keyAndClaims) {
      SignatureVerifier signatureVerifier = new RsaVerifier((RSAPublicKey) keyAndClaim.getKey());
      try {
        Jwt jwt = JwtHelper.decodeAndVerify(idToken, signatureVerifier);
        Map<String, Object> claims = parseClaims(jwt);
        verifyExpiry(claims);

        if (validClaims(claims, keyAndClaim)) {
          return claims;
        }
      } catch (InvalidSignatureException exception) {
        LOGGER.error("Could not verify signature of id token", exception);
      }
    }
    LOGGER.error("The iss and/or aud claims do not match the required claims.");
    throw unauthorizedException();
  }

  private Map<String, Object> parseClaims(Jwt jwt) {
    try {
      return objectMapper.readValue(jwt.getClaims(), Map.class);
    } catch (IOException exception) {
      LOGGER.error("Unable to read the id token body", exception);
      throw unauthorizedException();
    }
  }

  private void verifyExpiry(Map claims) {
    if (!claims.containsKey(EXP)) {
      LOGGER.error("Token does not contain an expiry (exp) claim.");
      throw unauthorizedException();
    }

    Object expObj = claims.get(EXP);
    if (!(expObj instanceof Integer)) {
      LOGGER.error("The expiry (exp) claim is not an integer (epoch seconds).");
      throw unauthorizedException();
    }

    int exp = (int) claims.get(EXP);
    Date expireDate = new Date(exp * 1000L);
    Date now = new Date();
    if (expireDate.before(now)) {
      LOGGER.error("The id token has expired");
      throw unauthorizedException();
    }
  }

  private boolean validClaims(Map<String, Object> claims, KeyAndClaims keyAndClaims) {
    return keyAndClaims.getIss().equals(claims.get(ISS))
        && keyAndClaims.getAud().equals(claims.get(AUD));
  }

  private JwtAuthenticationException unauthorizedException() {
    return new JwtAuthenticationException("Unable to validate credentials");
  }
}
