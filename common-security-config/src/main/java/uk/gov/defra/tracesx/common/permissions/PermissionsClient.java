package uk.gov.defra.tracesx.common.permissions;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getEncoder;
import static java.util.Collections.emptyList;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.GET;

import com.microsoft.applicationinsights.TelemetryClient;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class PermissionsClient {

  private static final String ROLES = "roles";
  private static final String PERMISSIONS = "permissions";
  private static final String FORWARD_SLASH = "/";
  private static final String BASIC = "Basic ";
  private static final String COLON = ":";
  private static final String X_AUTH_HEADER_BASIC = "x-auth-basic";

  private static final String PERMISSIONS_RETRY_EVENT = "PermissionsRetryEvent";
  private static final Logger logger = LoggerFactory.getLogger(PermissionsClient.class);

  @Value("${permissions.service.scheme}")
  private String permissionsScheme;

  @Value("${permissions.service.host}")
  private String permissionsHost;

  @Value("${permissions.service.port}")
  private String permissionsPort;

  @Value("${permissions.service.user}")
  private String permissionsUser;

  @Value("${permissions.service.password}")
  private String permissionsPassword;

  @Value("${permissions.security.token-feature-switch}")
  private boolean securityTokenFeatureSwitch;

  private final RestTemplate permissionsRestTemplate;
  private final TelemetryClient telemetryClient;

  @Autowired
  PermissionsClient(RestTemplate permissionsRestTemplate,
      TelemetryClient telemetryClient) {
    this.permissionsRestTemplate = permissionsRestTemplate;
    this.telemetryClient = telemetryClient;
  }

  public List<String> permissionsList(final String role, final String authorisationToken) {

    final UriComponentsBuilder builder = getPath(role);

    final String encodedBasicAuth = BASIC + getEncoder().encodeToString(permissionsUser
            .concat(COLON)
            .concat(permissionsPassword)
            .getBytes(UTF_8));

    final HttpHeaders headers = new HttpHeaders();
    headers.set(X_AUTH_HEADER_BASIC, encodedBasicAuth);
    if (securityTokenFeatureSwitch && authorisationToken != null) {
      headers.add(AUTHORIZATION, authorisationToken);
    }
    final HttpEntity<String> entity = new HttpEntity<>(headers);

    final List<String> response = getPermissions(builder, entity);

    if (response == null) {
      return emptyList();
    }
    return response;
  }

  private List<String> getPermissions(final UriComponentsBuilder builder, final HttpEntity<String> entity) {
    List<String> permissions;
    try {
      permissions = permissionsRestTemplate
          .exchange(builder.build().encode().toUri(), GET, entity,
              new ParameterizedTypeReference<List<String>>() {})
          .getBody();
    } catch (ResourceAccessException e) {
      telemetryClient.trackEvent(PERMISSIONS_RETRY_EVENT);
      logger.error("Call to permissions from Economic Operator failed");
      throw e;
    }
    return permissions;
  }

  private UriComponentsBuilder getPath(final String role) {
    return UriComponentsBuilder.newInstance()
        .scheme(permissionsScheme)
        .host(permissionsHost)
        .port(permissionsPort)
        .path(FORWARD_SLASH + ROLES)
        .pathSegment(role)
        .path(FORWARD_SLASH + PERMISSIONS);
  }
}