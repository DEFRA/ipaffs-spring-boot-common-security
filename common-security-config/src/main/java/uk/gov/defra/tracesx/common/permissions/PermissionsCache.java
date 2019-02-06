package uk.gov.defra.tracesx.common.permissions;

import com.microsoft.applicationinsights.TelemetryClient;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
public class PermissionsCache {

  private static final String CACHE_REFRESH_EVENT_NAME_TEMPLATE = "%sPermissionsCacheRefreshed";
  public static final String CACHE_KEY = "permissions";

  private final PermissionsClient permissionsClient;
  private final TelemetryClient telemetryClient;

  @Value("${info.app.name}")
  private String appName;

  @Autowired
  PermissionsCache(PermissionsClient permissionsClient, TelemetryClient telemetryClient) {
    this.permissionsClient = permissionsClient;
    this.telemetryClient = telemetryClient;
  }

  @Cacheable(value = CACHE_KEY, key = "#role")
  public List<String> permissionsList(final String role, final String authorisationToken) {
    return permissionsClient.permissionsList(role, authorisationToken);
  }

  @CacheEvict(value = CACHE_KEY, allEntries=true)
  @Scheduled(fixedDelayString = "${cache.refreshDelay}")
  public void clearCache() {
    telemetryClient.trackEvent(cacheRefreshEventName());
  }

  private String cacheRefreshEventName() {
    String appNameTrimmed = appName
        .replace(" ", "")
        .replace("-", "")
        .trim();
    return String.format(CACHE_REFRESH_EVENT_NAME_TEMPLATE, appNameTrimmed);
  }
}
