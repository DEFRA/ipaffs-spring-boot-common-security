package uk.gov.defra.tracesx.common.security.tests;

import static io.restassured.RestAssured.given;
import static uk.gov.defra.tracesx.common.security.tests.Constants.X_AUTH_BASIC;
import static uk.gov.defra.tracesx.common.security.tests.Constants.X_AUTH_BASIC_VALUE;

import io.restassured.http.ContentType;
import org.junit.Test;

public abstract class AbstractAdminAuthenticationTest {

  /**
   * @return the url for the permissions's /admin path (of which /admin/info and /admin/healthcheck are child paths)
   */
  protected abstract String getAdminUrl();

  /**
   * @return the url for the permissions's root path
   */
  protected abstract String getRootUrl();

  @Test
  public void callRoot_withoutAuth_successfully() {
    given()
        .when()
        .get(getRootUrl())
        .then()
        .statusCode(200);
  }

  @Test
  public void callAdmin_withoutBasicAuth_successfully() {
    given()
        .contentType(ContentType.JSON)
        .when()
        .get(getAdminUrl())
        .then()
        .statusCode(200);
  }

  @Test
  public void callAdmin_withLegacyAuthHeader_headerIgnoredBackwardsCompatible() {
    given()
        .contentType(ContentType.JSON)
        .header(X_AUTH_BASIC, X_AUTH_BASIC_VALUE)
        .when()
        .get(getAdminUrl())
        .then()
        .statusCode(200);
  }
}
