package uk.gov.defra.tracesx.common.permissions;


import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.microsoft.applicationinsights.TelemetryClient;
import com.microsoft.applicationinsights.TelemetryConfiguration;
import java.util.Collections;
import java.util.List;
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
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
@ActiveProfiles("permissions-cache")
public class PermissionsCacheTest {

  @EnableCaching
  @Profile("permissions-cache")
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
      return spy(new TelemetryClient(configuration));
    }

  }

  @Autowired
  private PermissionsClient permissionsService;

  @Autowired
  private PermissionsCache permissionsCache;

  @Autowired
  private TelemetryClient telemetryClient;

  @Test
  public void permissionsList_calledTwice_remoteServiceCalledOnce() {
    List<String> firstList = Collections.singletonList("permissions1");
    List<String> secondList = Collections.singletonList("permissions2");
    when(permissionsService.permissionsList(anyString(), anyString())).thenReturn(firstList, secondList);

    List<String> result1 = permissionsCache.permissionsList("importer", "token");
    List<String> result2 = permissionsCache.permissionsList("importer", "token");

    assertThat(result1).containsOnlyElementsOf(firstList);
    assertThat(result2).containsOnlyElementsOf(firstList);

    verify(permissionsService).permissionsList("importer", "token");
  }

  @Test
  public void clearCache_whenCalled_emitsTelemetryEvent() {
    permissionsCache.clearCache();
    verify(telemetryClient).trackEvent("UnitTestAppPermissionsCacheRefreshed");
  }
}
