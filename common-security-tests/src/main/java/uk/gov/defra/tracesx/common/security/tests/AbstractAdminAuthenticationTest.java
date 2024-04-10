package uk.gov.defra.tracesx.common.security.tests;

import static io.restassured.RestAssured.given;
import static uk.gov.defra.tracesx.common.security.tests.Constants.X_AUTH_BASIC;
import static uk.gov.defra.tracesx.common.security.tests.Constants.X_AUTH_BASIC_VALUE;

import io.restassured.http.ContentType;
import org.junit.jupiter.api.Test;

public abstract class AbstractAdminAuthenticationTest {

  private ServiceTestHelper serviceTestHelper = new ServiceTestHelper();

  protected ServiceTestHelper getServiceTestHelper() {
    return serviceTestHelper;
  }

  @Test
  void callRoot_withoutAuth_successfully() {
    given().when().get(serviceTestHelper.getRootUrl()).then().statusCode(200);
  }

  @Test
  void callAdmin_withoutBasicAuth_successfully() {
    given()
        .contentType(ContentType.JSON)
        .when()
        .get(getServiceTestHelper().getAdminUrl())
        .then()
        .statusCode(200);
  }

  @Test
  void callAdmin_withLegacyAuthHeader_headerIgnoredBackwardsCompatible() {
    given()
        .contentType(ContentType.JSON)
        .header(X_AUTH_BASIC, X_AUTH_BASIC_VALUE)
        .when()
        .get(getServiceTestHelper().getAdminUrl())
        .then()
        .statusCode(200);
  }
}
