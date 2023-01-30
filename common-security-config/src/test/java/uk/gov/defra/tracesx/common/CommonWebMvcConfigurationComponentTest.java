package uk.gov.defra.tracesx.common;

import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.defra.tracesx.common.CommonWebMvcConfiguration.PERMISSIONS_REST_TEMPLATE_QUALIFIER;

import java.util.Collections;
import org.apache.http.client.config.RequestConfig;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;
import uk.gov.defra.tracesx.common.CommonWebMvcConfigurationComponentTest.Config;
import uk.gov.defra.tracesx.common.security.ServiceUrlPatterns;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = {Config.class, CommonWebMvcConfiguration.class})
@ActiveProfiles("webmvc-config")
public class CommonWebMvcConfigurationComponentTest {

  @Autowired
  @Qualifier(PERMISSIONS_REST_TEMPLATE_QUALIFIER)
  private RestTemplate permissionsRestTemplate;

  @Profile("webmvc-config")
  @Configuration
  static class Config {
    @Bean
    public ServiceUrlPatterns serviceUrlPatterns() {
      return () -> Collections.singletonList("test/**");
    }
  }

  @Test
  public void permissionRestTemplate_noTimeoutSpecified_defaultsUsedInstead() {
    HttpComponentsClientHttpRequestFactory factory =
        (HttpComponentsClientHttpRequestFactory) permissionsRestTemplate.getRequestFactory();
    RequestConfig requestConfig =
        (RequestConfig) ReflectionTestUtils.getField(factory, "requestConfig");
    assertThat(requestConfig.getConnectTimeout()).isEqualTo(25000);
    assertThat(requestConfig.getSocketTimeout()).isEqualTo(25000);
  }
}
