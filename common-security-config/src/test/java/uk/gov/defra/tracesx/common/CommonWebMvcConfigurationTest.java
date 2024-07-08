package uk.gov.defra.tracesx.common;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.ARRAY;

import com.microsoft.applicationinsights.TelemetryClient;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.util.List;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.CacheManager;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.handler.MappedInterceptor;
import uk.gov.defra.tracesx.common.security.jwks.JwksConfiguration;

@ExtendWith(MockitoExtension.class)
class CommonWebMvcConfigurationTest {

  private static final int CONNECTION_TIMEOUT = 1;
  private static final int READ_TIMEOUT = 2;
  private static final String CONNECTION_TIMEOUT_FIELD = "permissionsServiceConnectionTimeout";
  private static final String READ_TIMEOUT_FIELD = "permissionsServiceReadTimeout";
  private static final String SERVICE_URL_PATTERNS_FIELD = "serviceUrlPatterns";
  private static final String MALFORMED_TEST_URL = "test,next";
  private static final String TEST_URL = "http://www.example.com:1080/docs/resource1.html";

  private final CommonWebMvcConfiguration testee = new CommonWebMvcConfiguration();

  @BeforeEach
  public void setUp() throws IllegalAccessException {
    FieldUtils.writeField(testee, CONNECTION_TIMEOUT_FIELD, CONNECTION_TIMEOUT, true);
    FieldUtils.writeField(testee, READ_TIMEOUT_FIELD, READ_TIMEOUT, true);
    FieldUtils.writeField(testee, SERVICE_URL_PATTERNS_FIELD, new MockServiceUrlPatterns(), true);
  }

  @Test
  void whenPermissionsRestTemplateCalledReturnsValidConfiguration() {
    RestTemplate restTemplate = testee.permissionsRestTemplate();
    assertThat(restTemplate).isNotNull();
    // assert that Spring default message converters are registered
    assertThat(restTemplate.getMessageConverters()).isNotEmpty();
  }

  @Test
  void addInterceptors_ReturnsInterceptors_WhenItemsAreAddedToRegistryAndAccessible()
      throws InvocationTargetException, IllegalAccessException, NoSuchMethodException{
    InterceptorRegistry interceptorRegistry = new InterceptorRegistry();
    testee.addInterceptors(interceptorRegistry);
    Method retrieveItems = interceptorRegistry.getClass().getDeclaredMethod("getInterceptors");
    retrieveItems.setAccessible(true);
    List<MappedInterceptor> interceptorList =
        (List<MappedInterceptor>) retrieveItems.invoke(interceptorRegistry);

    assertThat(interceptorList).first()
        .extracting(MappedInterceptor::getIncludePathPatterns)
        .asInstanceOf(ARRAY)
        .containsExactlyInAnyOrderElementsOf(MockServiceUrlPatterns.PATTERNS);
  }

  @Test
  void jwksConfiguration_ThrowsMalformedURLException_WhenUrlIsInvalid() throws IllegalAccessException {
    FieldUtils.writeField(testee, "jwkUrl", MALFORMED_TEST_URL, true);
    FieldUtils.writeField(testee, "iss", MALFORMED_TEST_URL, true);
    FieldUtils.writeField(testee, "aud", MALFORMED_TEST_URL, true);
    assertThatThrownBy(testee::jwksConfiguration).isInstanceOf(MalformedURLException.class)
        .hasMessageContaining("no protocol: test");
  }

  @Test
  void jwksConfiguration_ReturnsJwksConfigurationsList_WhenVariablesAreValid()
      throws MalformedURLException, IllegalAccessException {
    FieldUtils.writeField(testee, "jwkUrl", TEST_URL, true);
    FieldUtils.writeField(testee, "iss", TEST_URL, true);
    FieldUtils.writeField(testee, "aud", TEST_URL, true);

    List<JwksConfiguration> jwksConfigurations = testee.jwksConfiguration();

    assertThat(jwksConfigurations).isNotEmpty();
  }

  @Test
  void jwksConfiguration_ThrowsIllegalArgumentException_WhenVariableListsAreDifferentLengths()
      throws IllegalAccessException {
    FieldUtils.writeField(testee, "aud", MALFORMED_TEST_URL, true);
    FieldUtils.writeField(testee, "jwkUrl", TEST_URL, true);
    FieldUtils.writeField(testee, "iss", MALFORMED_TEST_URL, true);

    assertThatThrownBy(testee::jwksConfiguration).isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("The comma-separated properties spring.security.jwt.[jwks, iss, aud] must all have the same number of elements.");
  }

  @Test
  void telemetryClient_ReturnsInstance_WhenCalled() {
    //When
    TelemetryClient telemetryClient = testee.telemetryClient();

    //Then
    assertThat(telemetryClient).isNotNull();
  }

  @Test
  void cacheManager_ReturnsInstance_WhenCalled() {
    //When
    CacheManager cacheManager = testee.cacheManager();

    //Then
    assertThat(cacheManager).isNotNull();
  }
}
