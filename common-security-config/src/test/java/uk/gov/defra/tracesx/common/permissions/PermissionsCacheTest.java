package uk.gov.defra.tracesx.common.permissions;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.microsoft.applicationinsights.TelemetryClient;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.Test;
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

@SpringBootTest
@ActiveProfiles("permissions-cache")
class PermissionsCacheTest {

  @Autowired
  private PermissionsClient permissionsService;
  @Autowired
  private PermissionsCache permissionsCache;
  @Autowired
  private TelemetryClient telemetryClient;

  @Test
   void permissionsList_calledTwice_remoteServiceCalledOnce() {
    List<String> firstList = Collections.singletonList("permissions1");
    List<String> secondList = Collections.singletonList("permissions2");
    when(permissionsService.permissionsList(anyString(), anyString())).thenReturn(firstList,
        secondList);

    List<String> result1 = permissionsCache.permissionsList("importer", "token");
    List<String> result2 = permissionsCache.permissionsList("importer", "token");

    assertThat(result1).containsOnlyElementsOf(firstList);
    assertThat(result2).containsOnlyElementsOf(firstList);

    verify(permissionsService).permissionsList("importer", "token");
  }

  @Test
  void clearCache_whenCalled_emitsTelemetryEvent() {
    permissionsCache.clearCache();
    verify(telemetryClient).trackEvent("UnitTestAppPermissionsCacheRefreshed");
  }

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
      return spy(new TelemetryClient());
    }
  }
}
