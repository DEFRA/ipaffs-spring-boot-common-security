package uk.gov.defra.tracesx.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.List;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.handler.MappedInterceptor;

@RunWith(MockitoJUnitRunner.class)
public class CommonWebMvcConfigurationTest {

  private static final int CONNECTION_TIMEOUT = 1;
  private static final int READ_TIMEOUT = 2;
  private static final String CONNECTION_TIMEOUT_FIELD = "permissionsServiceConnectionTimeout";
  private static final String READ_TIMEOUT_FIELD = "permissionsServiceReadTimeout";
  private static final String SERVICE_URL_PATTERNS_FIELD = "serviceUrlPatterns";
  private static final String BASE_URL_MATCHER = "/countries/*";
  private static final String COUNTRIES_URL_MATCHER = "/countries";

  private final CommonWebMvcConfiguration testee = new CommonWebMvcConfiguration();

  @Before
  public void setUp() throws IllegalAccessException {
    FieldUtils.writeField(testee, CONNECTION_TIMEOUT_FIELD, CONNECTION_TIMEOUT, true);
    FieldUtils.writeField(testee, READ_TIMEOUT_FIELD, READ_TIMEOUT, true);
    FieldUtils.writeField(testee, SERVICE_URL_PATTERNS_FIELD, new MockServiceUrlPatterns(), true);
  }

  @Test
  public void whenPermissionsRestTemplateCalledReturnsValidConfiguration() {
    RestTemplate restTemplate = testee.permissionsRestTemplate();
    assertThat(restTemplate).isNotNull();
    // assert that Spring default message converters are registered
    assertThat(restTemplate.getMessageConverters()).isNotEmpty();
  }

  @Test
  public void whenAddInterceptorsThenReturnInterceptors() throws InvocationTargetException, IllegalAccessException, NoSuchMethodException{
    InterceptorRegistry interceptorRegistry = new InterceptorRegistry();
    testee.addInterceptors(interceptorRegistry);
    interceptorRegistry.getClass().getDeclaredMethod("getInterceptors");
    Method retrieveItems = interceptorRegistry.getClass().getDeclaredMethod("getInterceptors");
    retrieveItems.setAccessible(true);
    List<MappedInterceptor> interceptorList = (List<MappedInterceptor>)retrieveItems.invoke(interceptorRegistry);

    assertThat(interceptorList).isNotNull();
    assertThat(interceptorList).isNotEmpty();
    assertThat(interceptorList.get(0).getPathPatterns()).containsExactlyInAnyOrderElementsOf(MockServiceUrlPatterns.PATTERNS);
  }
}
