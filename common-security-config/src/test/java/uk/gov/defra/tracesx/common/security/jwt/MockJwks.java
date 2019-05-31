package uk.gov.defra.tracesx.common.security.jwt;

import com.auth0.jwk.Jwk;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import io.jsonwebtoken.Jwts;
import java.lang.reflect.Method;
import java.security.KeyPair;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Builder;
import lombok.Getter;

public class MockJwks {

  public static final String JWKS_URL1 = "https://provider-one.com/jwks";
  public static final String JWKS_ISSUER1 = "https://provider-one.com";
  public static final String JWKS_AUDIENCE1 = "08ece0b1-2e8d-4c12-9f85-b8f758a3f977";

  public static final String JWKS_URL2 = "https://provider-two.com/jwks";
  public static final String JWKS_ISSUER2 = "https://provider-two.com";
  public static final String JWKS_AUDIENCE2 = "20ffdf69-9430-4791-86c2-dd86b6186112";

  public static final String SUB_VALUE = "14f30ce2-114f-4375-982f-68c43023ce02";
  public static final String ORG_ID = "3199a90f-a670-e911-a974-000d3a28da35";
  public static final List<String> ROLES_VALUE = Collections.singletonList("ROLE1");

  public static final RSAKey NIMBUS_KEY1 = createNimbusKey();
  public static final KeyPair KEY_PAIR1 = toKeyPair(NIMBUS_KEY1);
  public static final JwkElement JWK_ELEMENT1 = createJwkElement(NIMBUS_KEY1);
  public static final Jwk JWK1 = createJwkForProvider(NIMBUS_KEY1);
  public static final RSAKey NIMBUS_KEY2 = createNimbusKey();
  public static final KeyPair KEY_PAIR2 = toKeyPair(NIMBUS_KEY2);
  public static final JwkElement JWK_ELEMENT2 = createJwkElement(NIMBUS_KEY2);
  public static final Jwk JWK2 = createJwkForProvider(NIMBUS_KEY2);

  private static RSAKey createNimbusKey() {
    try {
    return new RSAKeyGenerator(2048)
        .keyUse(KeyUse.SIGNATURE) // indicate the intended use of the key
        .keyID(UUID.randomUUID().toString()) // give the key a unique ID
        .generate();
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  private static KeyPair toKeyPair(RSAKey nimbusKey) {
    try {
      return nimbusKey.toKeyPair();
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  public static String createToken1(Date exp) {
    return Jwts.builder()
        .setHeader(Collections.singletonMap("kid", JWK_ELEMENT1.getKid()))
        .setExpiration(exp)
        .claim("aud", JWKS_AUDIENCE1)
        .claim("iss", JWKS_ISSUER1)
        .claim("sub", SUB_VALUE)
        .claim("roles", ROLES_VALUE)
        .claim("customer_organisation_id", ORG_ID)
        .signWith(KEY_PAIR1.getPrivate())
        .compact();
  }

  public static String createToken2(Date exp) {
    return Jwts.builder()
        .setHeader(Collections.singletonMap("kid", JWK_ELEMENT2.getKid()))
        .setExpiration(exp)
        .claim("aud", JWKS_AUDIENCE2)
        .claim("iss", JWKS_ISSUER2)
        .claim("sub", SUB_VALUE)
        .claim("roles", ROLES_VALUE)
        .claim("customer_organisation_id", ORG_ID)
        .signWith(KEY_PAIR2.getPrivate())
        .compact();
  }

  private static Jwk createJwkForProvider(RSAKey key) {
    try {
      ObjectMapper objectMapper = new ObjectMapper();
      JwkElement element = createJwkElement(key);
      String elementString = objectMapper.writeValueAsString(element);
      Map<String, Object> values = objectMapper.readValue(elementString, Map.class);
      Method fromValuesMethod = Jwk.class.getDeclaredMethod("fromValues", Map.class);
      fromValuesMethod.setAccessible(true);
      return (Jwk) fromValuesMethod.invoke(null, values);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static JwkElement createJwkElement(RSAKey rsaKey) {
    try {
      return JwkElement.builder()
          .n(rsaKey.getModulus().toString())
          .e(rsaKey.getPublicExponent().toString())
          .kid(rsaKey.computeThumbprint().toString())
          .x5t(rsaKey.computeThumbprint().toString())
          .build();
    } catch (JOSEException e) {
      throw new RuntimeException(e);
    }
  }

  @Getter
  @Builder
  public static class JwkElement {
    private final String alg = "RS256";
    private final String kty = "RSA";
    private final String use = "sig";
    private String n;
    private String e;
    private String kid;
    private String x5t;
  }

}
