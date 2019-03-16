package uk.gov.defra.tracesx.common.permissions;


import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.microsoft.applicationinsights.TelemetryClient;
import com.microsoft.applicationinsights.TelemetryConfiguration;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.support.SimpleCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("cache-test")
public class PermissionsCacheTest {

  @EnableCaching
  @Profile("cache-test")
  @Configuration
  static class Config {

    @Bean
    PermissionsClient permissionsClient() {
      return Mockito.mock(PermissionsClient.class);
    }

    @Bean
    CacheManager cacheManager() {
      SimpleCacheManager cacheManager = new SimpleCacheManager();
      cacheManager.setCaches(Collections.singletonList(new ConcurrentMapCache("permissions")));
      return cacheManager;
    }

    @Bean
    public PermissionsCache getPermissionsCache() {
      return new PermissionsCache(this.permissionsClient(), this.getTelemetryClient());
    }

    @Bean
    public TelemetryClient getTelemetryClient() {
      TelemetryConfiguration configuration = TelemetryConfiguration.getActive();
      return new TelemetryClient(configuration);
    }

//    @Bean
//    public static PropertySourcesPlaceholderConfigurer properties() {
//      final PropertySourcesPlaceholderConfigurer pspc = new PropertySourcesPlaceholderConfigurer();
//      Properties properties = new Properties();
//      properties.setProperty("service.security.token-feature-switch", "true");
//      pspc.setProperties(properties);
//      return pspc;
//    }
  }

  @Autowired
  PermissionsClient permissionsService;

  @Autowired
  private PermissionsCache permissionsCache;

  @Before
  public void setUp() {
  }

  @Test
  public void givenPermissionsServiceMocked_WhenPermissionsRetrieved_ThenServiceCalledOnce() {

    List<String> firstList = Collections.singletonList("permissions1");
    List<String> secondList = Collections.singletonList("permissions2");
    when(permissionsService.permissionsList(anyString(), anyString())).thenReturn(firstList, secondList);

    List<String> result1 = permissionsCache.permissionsList("importer", "token");
    List<String> result2 = permissionsCache.permissionsList("importer", "token");

    verify(permissionsService, times(1)).permissionsList("importer",
            "token");
    assertThat(result1.get(0)).isEqualToIgnoringCase("permissions1");
    assertThat(result2.get(0)).isEqualToIgnoringCase("permissions1");
  }
}
