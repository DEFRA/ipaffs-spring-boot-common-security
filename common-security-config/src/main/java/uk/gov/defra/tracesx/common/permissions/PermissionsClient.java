package uk.gov.defra.tracesx.common.permissions;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Base64.getEncoder;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.GET;
import static uk.gov.defra.tracesx.common.CommonWebMvcConfiguration.PERMISSIONS_REST_TEMPLATE_QUALIFIER;

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

import java.util.List;
import java.util.Optional;

@Component
public class PermissionsClient {
  private static final String BASIC = "Basic ";
  private static final String X_AUTH_HEADER_BASIC = "x-auth-basic";

  private static final Logger LOGGER = LoggerFactory.getLogger(PermissionsClient.class);

  @Value("${permissions.service.scheme:#{null}}")
  private String permissionsScheme;

  @Value("${permissions.service.host:#{null}}")
  private String permissionsHost;

  @Value("${permissions.service.port:#{null}}")
  private String permissionsPort;

  @Value("${permissions.service.url:#{null}}")
  private String permissionsUrl;

  @Value("${permissions.service.user}")
  private String permissionsUser;

  @Value("${permissions.service.password}")
  private String permissionsPassword;

  @Value("${permissions.security.token-feature-switch}")
  private boolean securityTokenFeatureSwitch;

  private RestTemplate permissionsRestTemplate;

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
            // Fall back to old environment naming standard during migration from old to new in services that use the
            // security commons.
            .orElseGet(() -> UriComponentsBuilder.newInstance()
                    .scheme(Optional.ofNullable(permissionsScheme)
                            .orElseThrow(() -> createPropertyNotFoundException("permissions.service.scheme")))
                    .host(Optional.ofNullable(permissionsHost)
                            .orElseThrow(() -> createPropertyNotFoundException("permissions.service.host")))
                    .port(Optional.ofNullable(permissionsPort)
                            .orElseThrow(() -> createPropertyNotFoundException("permissions.service.port")))
            ).path("/roles")
        .pathSegment(role)
        .path("/permissions");
  }

  private IllegalArgumentException createPropertyNotFoundException(String propertyName) {
    return new IllegalArgumentException(
            "Could not resolve permission client placeholder 'prmissions.service.url' or fall back '"
                    + propertyName + "'");
  }

  private HttpHeaders getHeaders(String authorisationToken) {
    String encodedBasicAuth =
        BASIC
            + getEncoder()
                .encodeToString(
                    permissionsUser.concat(":").concat(permissionsPassword).getBytes(UTF_8));

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
          .exchange(
              builder.build().encode().toUri(),
              GET,
              entity,
              new ParameterizedTypeReference<List<String>>() {})
          .getBody();
    } catch (ResourceAccessException exception) {
      LOGGER.warn("Unable to get permissions", exception);
      throw exception;
    }
  }
}
