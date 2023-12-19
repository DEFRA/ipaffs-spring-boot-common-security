package uk.gov.defra.tracesx.common;

import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.defra.tracesx.common.CommonWebMvcConfiguration.PERMISSIONS_REST_TEMPLATE_QUALIFIER;

import java.util.Collections;
import java.util.concurrent.TimeUnit;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.core5.util.Timeout;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;
import uk.gov.defra.tracesx.common.CommonWebMvcConfigurationComponentTest.Config;
import uk.gov.defra.tracesx.common.security.ServiceUrlPatterns;

@SpringBootTest(classes = {Config.class, CommonWebMvcConfiguration.class})
@ActiveProfiles("webmvc-config")
class CommonWebMvcConfigurationComponentTest {

  @Autowired
  @Qualifier(PERMISSIONS_REST_TEMPLATE_QUALIFIER)
  private RestTemplate permissionsRestTemplate;

  @Test
  void permissionRestTemplate_noTimeoutSpecified_defaultsUsedInstead() {
    HttpComponentsClientHttpRequestFactory factory =
        (HttpComponentsClientHttpRequestFactory) permissionsRestTemplate.getRequestFactory();

    ConnectionConfig connectionConfig = ConnectionConfig.custom()
        .setConnectTimeout(25000, TimeUnit.MILLISECONDS)
        .setSocketTimeout(25000, TimeUnit.MILLISECONDS)
        .build();

    assertThat(connectionConfig.getConnectTimeout()).isEqualTo(Timeout.ofMilliseconds(25000));
    assertThat(connectionConfig.getSocketTimeout()).isEqualTo(Timeout.ofMilliseconds(25000));
  }

  @Profile("webmvc-config")
  @Configuration
  static class Config {

    @Bean
    public ServiceUrlPatterns serviceUrlPatterns() {
      return () -> Collections.singletonList("test/**");
    }
  }
}
