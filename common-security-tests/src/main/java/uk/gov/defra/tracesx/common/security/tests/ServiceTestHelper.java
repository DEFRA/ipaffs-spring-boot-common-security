package uk.gov.defra.tracesx.common.security.tests;

import static uk.gov.defra.tracesx.common.security.tests.jwt.JwtConstants.BEARER;

import org.apache.commons.lang3.StringUtils;

import java.util.function.Supplier;

/**
 * Override this class for additional paths in service specific tests.
 */
public class ServiceTestHelper {

  public static final String AUTHORIZATION = "Authorization";

  public ServiceTestHelper() {
    assertNotNullOrEmpty(getServiceBaseUrl(), "Url is empty");
  }

  private void assertNotNullOrEmpty(String value, String message) {
    if (StringUtils.isBlank(value)) {
      throw new NullPointerException(message);
    }
  }

  public String getJwtAuthHeaderName() {
    return AUTHORIZATION;
  }

  public String getJwtTokenHeaderValue(String token) {
    return BEARER + token;
  }

  public String getServiceUsername() {
    return CommonProperties.SERVICE_USERNAME;
  }

  public String getServicePassword() {
    return CommonProperties.SERVICE_PASSWORD;
  }

  protected String getServiceBaseUrl() {
    return CommonProperties.SERVICE_BASE_URL;
  }

  public String getRootUrl() {
    return getServiceBaseUrl() + "/";
  }

  protected String getAdminUrl() {
    return getServiceBaseUrl() + "/admin";
  }

  public String getUrl(String path) {
    return getServiceBaseUrl() + path;
  }

  protected String getResourceUrl(Supplier<String> resourceRootSupplier, String path) {
    return getUrl(resourceRootSupplier.get() + path);
  }
}
