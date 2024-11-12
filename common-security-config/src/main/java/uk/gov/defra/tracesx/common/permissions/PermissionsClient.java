package uk.gov.defra.tracesx.common.permissions;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.GET;
import static uk.gov.defra.tracesx.common.CommonWebMvcConfiguration.PERMISSIONS_REST_TEMPLATE_QUALIFIER;

import java.util.List;
import java.util.Optional;
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

  @Value("${permissions.service.url:#{null}}")
  private String permissionsUrl;

  private final RestTemplate permissionsRestTemplate;

  @Autowired
  public PermissionsClient(
      @Qualifier(PERMISSIONS_REST_TEMPLATE_QUALIFIER) RestTemplate permissionsRestTemplate) {
    this.permissionsRestTemplate = permissionsRestTemplate;
  }

  List<String> permissionsList(String role, String authorisationToken) {
    UriComponentsBuilder uriComponentsBuilder = getPath(role);
    HttpHeaders httpHeaders = getHeaders(authorisationToken);
    HttpEntity<String> httpEntity = new HttpEntity<>(httpHeaders);
    return getPermissions(uriComponentsBuilder, httpEntity);
  }

  UriComponentsBuilder getPath(String role) {
    return Optional.ofNullable(permissionsUrl)
        .map(UriComponentsBuilder::fromUriString)
        .orElseThrow(() -> createPropertyNotFoundException("permissions.service.port"))
        .path("/roles")
        .pathSegment(role)
        .path("/permissions");
  }

  private IllegalArgumentException createPropertyNotFoundException(String propertyName) {
    return new IllegalArgumentException(
        "Could not resolve permission client placeholder '" + propertyName + "'");
  }

  private HttpHeaders getHeaders(String authorisationToken) {
    HttpHeaders headers = new HttpHeaders();
    headers.add(AUTHORIZATION, authorisationToken);
    return headers;
  }

  private List<String> getPermissions(UriComponentsBuilder builder, HttpEntity<String> entity) {
    try {
      return permissionsRestTemplate
          .exchange(
              builder.build().encode().toUri(),
              GET,
              entity,
              new ParameterizedTypeReference<List<String>>() {
              })
          .getBody();
    } catch (ResourceAccessException exception) {
      throw new ResourceAccessException("Unable to get permissions due to exception: " + exception);
    }
  }
}

