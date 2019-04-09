package uk.gov.defra.tracesx.common.security.tests.jwt;

import static io.restassured.RestAssured.given;
import static org.apache.http.HttpHeaders.AUTHORIZATION;
import static uk.gov.defra.tracesx.common.security.tests.CommonProperties.TEST_OPENID_TOKEN_SERVICE_AUTH_PASSWORD;
import static uk.gov.defra.tracesx.common.security.tests.CommonProperties.TEST_OPENID_TOKEN_SERVICE_AUTH_USERNAME;
import static uk.gov.defra.tracesx.common.security.tests.CommonProperties.TEST_OPENID_TOKEN_SERVICE_URL;
import static uk.gov.defra.tracesx.common.security.tests.jwt.JwtConstants.EXP;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class SelfSignedTokenClient {

  private static final String TEST_OPENID_BASIC;

  static {
    String encodedBasicAuth =
        Base64.getEncoder()
            .encodeToString(
                (TEST_OPENID_TOKEN_SERVICE_AUTH_USERNAME + ":"
                    + TEST_OPENID_TOKEN_SERVICE_AUTH_PASSWORD).getBytes(StandardCharsets.UTF_8));
    TEST_OPENID_BASIC = "Basic " + encodedBasicAuth;
  }

  private final ObjectMapper objectMapper;

  public SelfSignedTokenClient() {
    objectMapper = new ObjectMapper();
  }

  public String getToken(TokenType tokenType) {
    return getToken(tokenType, Collections.emptyMap());
  }

  public String getExpiredToken(TokenType tokenType) {
    Map<String, Object> overrides = new HashMap<>();
    addExpiredTokenBodyOverride(overrides);
    return getToken(tokenType, overrides);
  }

  public String getTokenWithClaim(TokenType tokenType, String claimName, String claimValue) {
    return getToken(tokenType, Collections.singletonMap(claimName, claimValue));
  }

  private String getToken(TokenType tokenType, Map<String, Object> overrides) {
    String body;
    try {
      body = objectMapper.writeValueAsString(overrides);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException(e);
    }
    Response response = given()
        .header(AUTHORIZATION, TEST_OPENID_BASIC)
        .header("Content-Type", "application/json")
        .when()
        .body(body)
        .post(createUrl(tokenType, "/sign"));
    response.then()
        .statusCode(200);
    return response.getBody().asString();
  }

  private String createUrl(TokenType tokenType, String path) {
    return TEST_OPENID_TOKEN_SERVICE_URL + tokenType.getPrefix() + path;
  }

  private void addExpiredTokenBodyOverride(Map<String, Object> overrides) {
    long exp = LocalDateTime.now().minusDays(1).toInstant(ZoneOffset.UTC).toEpochMilli() / 1000L;
    overrides.put(EXP, exp);
  }

  public enum TokenType {
    AD("/ad"), B2C("/b2c");

    private final String prefix;

    TokenType(String s) {
      this.prefix = s;
    }

    public String getPrefix() {
      return prefix;
    }
  }

}
