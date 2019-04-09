package uk.gov.defra.tracesx.common.permissions;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getEncoder;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.GET;
import static uk.gov.defra.tracesx.common.CommonWebMvcConfiguration.PERMISSIONS_REST_TEMPLATE_QUALIFIER;

import com.microsoft.applicationinsights.TelemetryClient;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
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

  private static final String BASIC = "Basic ";
  private static final String X_AUTH_HEADER_BASIC = "x-auth-basic";

  private static final Logger LOGGER = LoggerFactory.getLogger(PermissionsClient.class);

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

  private RestTemplate permissionsRestTemplate;
  private TelemetryClient telemetryClient;

  @Autowired
  public PermissionsClient(@Qualifier(PERMISSIONS_REST_TEMPLATE_QUALIFIER) RestTemplate permissionsRestTemplate,
      TelemetryClient telemetryClient) {
    this.permissionsRestTemplate = permissionsRestTemplate;
    this.telemetryClient = telemetryClient;
  }

  public List<String> permissionsList(String role, String authorisationToken) {
    UriComponentsBuilder uriComponentsBuilder = getPath(role);
    HttpHeaders httpHeaders = getHeaders(authorisationToken);
    HttpEntity<String> httpEntity = new HttpEntity<>(httpHeaders);
    return getPermissions(uriComponentsBuilder, httpEntity);
  }

  private UriComponentsBuilder getPath(String role) {
    return UriComponentsBuilder.newInstance()
        .scheme(permissionsScheme)
        .host(permissionsHost)
        .port(permissionsPort)
        .path("/roles")
        .pathSegment(role)
        .path("/permissions");
  }

  private HttpHeaders getHeaders(String authorisationToken) {
    String encodedBasicAuth = BASIC + getEncoder().encodeToString(permissionsUser
        .concat(":")
        .concat(permissionsPassword)
        .getBytes(UTF_8));

    HttpHeaders headers = new HttpHeaders();
    headers.set(X_AUTH_HEADER_BASIC, encodedBasicAuth);
    if (securityTokenFeatureSwitch && authorisationToken != null) {
      headers.add(AUTHORIZATION, authorisationToken);
    }
    return headers;
  }

  private List<String> getPermissions(UriComponentsBuilder builder, HttpEntity<String> entity) {
    try {
      return permissionsRestTemplate
          .exchange(builder.build().encode().toUri(), GET, entity,
              new ParameterizedTypeReference<List<String>>() {})
          .getBody();
    } catch (ResourceAccessException e) {
      LOGGER.warn("Unable to get permissions", e);
      throw e;
    }
  }

}