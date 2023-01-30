package uk.gov.defra.tracesx.common.security.tests;

import static io.restassured.RestAssured.given;
import static uk.gov.defra.tracesx.common.security.tests.jwt.JwtConstants.AUD;
import static uk.gov.defra.tracesx.common.security.tests.jwt.JwtConstants.BEARER;
import static uk.gov.defra.tracesx.common.security.tests.jwt.JwtConstants.ISS;
import static uk.gov.defra.tracesx.common.security.tests.jwt.SelfSignedTokenClient.TokenType.AD;
import static uk.gov.defra.tracesx.common.security.tests.jwt.SelfSignedTokenClient.TokenType.B2C;

import io.restassured.http.ContentType;
import io.restassured.specification.RequestSpecification;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theory;
import uk.gov.defra.tracesx.common.security.tests.jwt.SelfSignedTokenClient;
import uk.gov.defra.tracesx.common.security.tests.jwt.SelfSignedTokenClient.TokenType;

@SuppressWarnings("unused")
public abstract class AbstractApiAuthenticationTest {

  public static final String DATA_POINTS_NAME = "API Methods";
  private static final String TOKEN_INVALID_SIGNATURE =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9l"
          + "IiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  private static final String AUTHORIZATION = "Authorization";

  private final SelfSignedTokenClient tokenClient = new SelfSignedTokenClient();

  @SuppressWarnings("squid:S2386")
  @DataPoints("Token Types")
  public static final TokenType[] tokenTypes = new TokenType[]{AD, B2C};

  @Theory
  public void callApi_withoutBearerToken_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod) {
    RequestSpecification spec = given().contentType(ContentType.JSON);
    apiMethod.call(spec).then().statusCode(401);
  }

  @Theory
  public void callApi_withIncorrectAuthorizationType_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(AUTHORIZATION, "Basic " + TOKEN_INVALID_SIGNATURE);
    apiMethod.call(spec).then().statusCode(401);
  }

  @Theory
  public void callApi_withUnrecognisedSignature_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(AUTHORIZATION, BEARER + TOKEN_INVALID_SIGNATURE);
    apiMethod.call(spec).then().statusCode(401);
  }

  @Theory
  public void callApi_withExpiredToken_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod,
      @FromDataPoints("Token Types") TokenType tokenType) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(AUTHORIZATION, BEARER + tokenClient.getExpiredToken(tokenType));
    apiMethod.call(spec).then().statusCode(401);
  }

  @Theory
  public void callApi_withIncorrectAudience_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod,
      @FromDataPoints("Token Types") TokenType tokenType) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(
                AUTHORIZATION,
                BEARER + tokenClient.getTokenWithClaim(tokenType, AUD, "invalid-audience"));
    apiMethod.call(spec).then().statusCode(401);
  }

  @Theory
  public void callApi_withIncorrectIssuer_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod,
      @FromDataPoints("Token Types") TokenType tokenType) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(
                AUTHORIZATION,
                BEARER + tokenClient.getTokenWithClaim(tokenType, ISS, "invalid-issuer"));
    apiMethod.call(spec).then().statusCode(401);
  }
}
