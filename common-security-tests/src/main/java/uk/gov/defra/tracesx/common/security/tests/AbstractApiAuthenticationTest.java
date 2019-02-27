package uk.gov.defra.tracesx.common.security.tests;

import static io.restassured.RestAssured.given;
import static uk.gov.defra.tracesx.common.security.tests.jwt.JwtConstants.*;

import io.restassured.http.ContentType;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.FromDataPoints;
import org.junit.experimental.theories.Theory;
import uk.gov.defra.tracesx.common.security.tests.jwt.SelfSignedTokenClient;
import uk.gov.defra.tracesx.common.security.tests.jwt.SelfSignedTokenClient.TokenType;
import static uk.gov.defra.tracesx.common.security.tests.jwt.SelfSignedTokenClient.TokenType.*;

/**
 * <p>To use: extend this class and declare a static @DataPoints field named {@link #DATA_POINTS_NAME}
 * that is an array of lambda which consume a {@link RequestSpecification} and produce a {@link
 * Response}. The {@link RequestSpecification} provided to the lambda will already contain the
 * security headers required for the test. The lambda should provide any further parameters and call
 * the appropriate method to complete the request e.g. {@link RequestSpecification#get()} or {@link
 * RequestSpecification#post()}. There should be a lambda for every API exposed by the service so
 * that security of each endpoint can be verified.</p>
 *
 * <p>The subclass needs to be annotated <pre>@RunWith(Theories.class)</pre>.</p>
 *
 * <p>Example: </p>
 * <code>
 *   \@DataPoints(DATA_POINTS_NAME)
 *   public ApiMethod[] getApiMethods() {
 *     return new ApiMethod[]{
 *         spec -> spec.get(helper.getAllCountries()),
 *         spec -> spec.get(helper.getNonUKCountries()),
 *         spec -> spec.get(helper.getCountryById("MY")),
 *         spec -> spec.post(helper.postCountries()),
 *         spec -> spec.delete(helper.deleteCountries("AB"))
 *     };
 *   }
 * </code>
 */
@SuppressWarnings("unused")
public abstract class AbstractApiAuthenticationTest {

  public static final String DATA_POINTS_NAME = "API Methods";
  private static final String TOKEN_INVALID_SIGNATURE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
  private static final String AUTHORIZATION = "Authorization";

  private final SelfSignedTokenClient tokenClient = new SelfSignedTokenClient();

  @DataPoints("Token Types")
  public static TokenType[] tokenTypes = new TokenType[]{AD, B2C};

  @Theory
  public void callApi_withoutBearerToken_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON);
    apiMethod.call(spec)
        .then()
        .statusCode(401);
  }

  @Theory
  public void callApi_withIncorrectAuthorizationType_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(AUTHORIZATION, "Basic " + TOKEN_INVALID_SIGNATURE);
    apiMethod.call(spec)
        .then()
        .statusCode(401);
  }

  @Theory
  public void callApi_withUnrecognisedSignature_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(AUTHORIZATION, BEARER + TOKEN_INVALID_SIGNATURE);
    apiMethod.call(spec)
        .then()
        .statusCode(401);
  }

  @Theory
  public void callApi_withExpiredToken_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod,
      @FromDataPoints("Token Types") TokenType tokenType) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(AUTHORIZATION, BEARER + tokenClient.getExpiredToken(tokenType));
    apiMethod.call(spec)
        .then()
        .statusCode(401);
  }

  @Theory
  public void callApi_withIncorrectAudience_respondsWith401Error(
      @FromDataPoints("API Methods") ApiMethod apiMethod,
      @FromDataPoints("Token Types") TokenType tokenType) {
    RequestSpecification spec =
        given()
            .contentType(ContentType.JSON)
            .header(
                AUTHORIZATION, BEARER
                    + tokenClient.getTokenWithClaim(tokenType, AUD, "invalid-audience"));
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
                BEARER
                    + tokenClient.getTokenWithClaim(tokenType, ISS, "invalid-issuer"));
    apiMethod.call(spec).then().statusCode(401);
  }
}
