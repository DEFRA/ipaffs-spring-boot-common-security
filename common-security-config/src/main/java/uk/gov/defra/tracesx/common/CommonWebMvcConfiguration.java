package uk.gov.defra.tracesx.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import uk.gov.defra.tracesx.common.security.PreAuthorizeChecker;
import uk.gov.defra.tracesx.common.security.ServiceUrlPatterns;
import uk.gov.defra.tracesx.common.security.jwks.JwksConfiguration;

@Configuration
@EnableConfigurationProperties
public class CommonWebMvcConfiguration implements WebMvcConfigurer {

  public static final String PERMISSIONS_REST_TEMPLATE_BEAN_NAME = "permissionsRestTemplate";

  @Value("${permissions.service.connectionTimeout}")
  private int permissionsServiceConnectionTimeout;

  @Value("${permissions.service.readTimeout}")
  private int permissionsServiceReadTimeout;

  @Bean(PERMISSIONS_REST_TEMPLATE_BEAN_NAME)
  public RestTemplate permissionsRestTemplate() {
    return createRestTemplate(
        permissionsServiceConnectionTimeout,
        permissionsServiceReadTimeout);
  }

  private RestTemplate createRestTemplate(final int connectionTimeout, final int readTimeout) {

    final HttpComponentsClientHttpRequestFactory clientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory();
    clientHttpRequestFactory.setConnectTimeout(connectionTimeout);
    clientHttpRequestFactory.setReadTimeout(readTimeout);

    final RestTemplate restTemplate = new RestTemplate(clientHttpRequestFactory);
    restTemplate.getMessageConverters().add(new StringHttpMessageConverter());

    return restTemplate;
  }

  @Value("${spring.security.jwt.jwks}")
  private String jwkUrl;

  @Value("${spring.security.jwt.iss}")
  private String iss;

  @Value("${spring.security.jwt.aud}")
  private String aud;

  @Bean
  @Qualifier("jwksConfiguration")
  public List<JwksConfiguration> jwksConfiguration() throws MalformedURLException {
    String[] jwkUrls = jwkUrl.split(",");
    String[] issuers = iss.split(",");
    String[] audiences = aud.split(",");
    List<JwksConfiguration> jwksConfigurations = new ArrayList<>();
    if(jwkUrls.length == issuers.length && issuers.length == audiences.length) {
      for(int i = 0; i < jwkUrls.length; i++) {
        jwksConfigurations.add(JwksConfiguration.builder()
            .jwksUrl(new URL(jwkUrls[i]))
            .issuer(issuers[i])
            .audience(audiences[i]).build());
      }
      return Collections.unmodifiableList(jwksConfigurations);
    } else {
      throw new RuntimeException("The comma-separated properties spring.security.jwt.[jwks, iss, aud] must all have the same number of elements.");
    }
  }

  @Autowired
  private ServiceUrlPatterns serviceUrlPatterns;

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(new PreAuthorizeChecker())
            .addPathPatterns(serviceUrlPatterns.getPatterns());
  }

}
