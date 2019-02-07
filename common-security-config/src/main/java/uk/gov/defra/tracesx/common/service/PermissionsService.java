package uk.gov.defra.tracesx.common.service;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getEncoder;
import static java.util.Collections.emptyList;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.GET;

import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class PermissionsService {

  private static final String ROLES = "roles";
  private static final String PERMISSIONS = "permissions";
  private static final String FORWARD_SLASH = "/";
  private static final String BASIC = "Basic ";
  private static final String COLON = ":";
  private static final String X_AUTH_HEADER_BASIC = "x-auth-basic";

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

  @Value("${service.security.token-feature-switch}")
  private boolean securityTokenFeatureSwitch;

  private final RestTemplate permissionsRestTemplate;

  @Autowired
  PermissionsService(final RestTemplate permissionsRestTemplate) {
    this.permissionsRestTemplate = permissionsRestTemplate;
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
    return permissionsRestTemplate
          .exchange(
              builder.build().encode().toUri(),
              GET,
              entity,
              new ParameterizedTypeReference<List<String>>() {
              })
          .getBody();
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