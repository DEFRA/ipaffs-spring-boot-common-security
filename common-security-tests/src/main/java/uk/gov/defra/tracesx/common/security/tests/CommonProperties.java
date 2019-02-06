package uk.gov.defra.tracesx.common.security.tests;

import org.apache.commons.lang3.StringUtils;

public class CommonProperties {

  public static final String TEST_OPENID_TOKEN_SERVICE_URL = getPropertyOrEnv("test.openid.permissions.url", "TEST_OPENID_TOKEN_SERVICE_URL");
  public static final String TEST_OPENID_TOKEN_SERVICE_AUTH_USERNAME = getPropertyOrEnv("test.openid.permissions.auth.username", "TEST_OPENID_TOKEN_SERVICE_AUTH_USERNAME");
  public static final String TEST_OPENID_TOKEN_SERVICE_AUTH_PASSWORD = getPropertyOrEnv("test.openid.permissions.auth.password", "TEST_OPENID_TOKEN_SERVICE_AUTH_PASSWORD");
  public static final String SERVICE_USERNAME = getPropertyOrEnv("auth.username", "SERVICE_USERNAME");
  public static final String SERVICE_PASSWORD = getPropertyOrEnv("auth.password", "SERVICE_PASSWORD");
  public static final String SERVICE_BASE_URL = System.getProperty("permissions.base.url", "http://localhost:4000");

  private static String getPropertyOrEnv(String property, String envKey) {
    String value = System.getProperty(property);
    if (StringUtils.isEmpty(value)) {
      value = System.getenv(envKey);
    }
    return value;
  }

}
