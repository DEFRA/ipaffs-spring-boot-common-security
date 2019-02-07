package uk.gov.defra.tracesx.common.security.jwks;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkException;
import java.security.Key;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;
import uk.gov.defra.tracesx.common.exceptions.InsSecurityException;

@Component
public class JwksCache {

  private static final Logger LOGGER = LoggerFactory.getLogger(JwksCache.class);

  private final List<ClaimsAwareJwkProvider> allJwkProviders;
  private final List<Map<String, ClaimsAwareJwkProvider>> cachedJwkProviders;

  public JwksCache(@Qualifier("jwksConfiguration") List<JwksConfiguration> jwksConfiguration, JwkProviderFactory jwkProviderFactory) {
    allJwkProviders =
        Collections.unmodifiableList(
            jwksConfiguration
                .stream()
                .map(jwkProviderFactory::newInstance)
                .collect(Collectors.toList()));
    cachedJwkProviders = new ArrayList<>();
  }

  public List<KeyAndClaims> getPublicKeys(String kid) {
    try {
      ArrayList<KeyAndClaims> keyAndClaims = new ArrayList<>();
      List<ClaimsAwareJwkProvider> jwkProviders = getJwkFromProviders(kid);

      for (ClaimsAwareJwkProvider jwkProvider : jwkProviders) {
        Jwk jwk = jwkProvider.get(kid);
        keyAndClaims.add(KeyAndClaims.builder()
            .aud(jwkProvider.getAudience())
            .iss(jwkProvider.getIssuer())
            .key(jwk.getPublicKey())
            .build());
      }
      return keyAndClaims;
    } catch (JwkException e) {
      LOGGER.error("Unable to get a public signing certificate for the id token", e);
      throw new InsSecurityException("Invalid security configuration");
    }
  }

  private List<ClaimsAwareJwkProvider> getJwkFromProviders(String kid) {
      List<ClaimsAwareJwkProvider> claimsAwareJwkProviders = cachedJwkProviders.stream()
              .filter(j -> j.containsKey(kid)).map(j -> j.get(kid)).collect(Collectors.toList());

      return claimsAwareJwkProviders.isEmpty() ? scanProviders(kid) : claimsAwareJwkProviders;
  }

  private List<ClaimsAwareJwkProvider> scanProviders(String kid) {
    List<ClaimsAwareJwkProvider> claimsAwareJwkProviders = new ArrayList<>();
    for(ClaimsAwareJwkProvider jwkProvider : allJwkProviders) {
      try {
        jwkProvider.get(kid);
        HashMap<String, ClaimsAwareJwkProvider> claimsAwareJwkProviderMap = new HashMap<>();
        claimsAwareJwkProviderMap.put(kid, jwkProvider);
        cachedJwkProviders.add(claimsAwareJwkProviderMap);
        claimsAwareJwkProviders.add(jwkProvider);
      } catch (JwkException e) {
        LOGGER.debug("Provider {} does not contain key {}", jwkProvider.getIssuer(), kid);
        LOGGER.debug("JwkProvider throw exception", e);
      }
    }
    if (claimsAwareJwkProviders.isEmpty()) {
      LOGGER.error("Unable to find any provider for key {}", kid);
      throw new InsSecurityException("Invalid security configuration");
    }
    return claimsAwareJwkProviders;
  }

  @Data
  @Builder
  @Getter
  @EqualsAndHashCode
  public static class KeyAndClaims {
    private String iss;
    private String aud;
    private Key key;
  }

}
