package uk.gov.defra.tracesx.common.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpMethod.GET;

import java.util.Arrays;
import java.util.List;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.http.protocol.HTTP;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.theories.Theories;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

public class PermissionsClientTest {

  private static final String X_AUTH_HEADER_BASIC = "x-auth-basic";

  private static final String SCHEME_FIELD = "permissionsScheme";
  private static final String SCHEME = "http";

  private static final String PERMISSIONS_USER_FIELD = "permissionsUser";
  private static final String PERMISSIONS_USER = "user";

  private static final String PERMISSIONS_USER_PASSWORD_FIELD = "permissionsPassword";
  private static final String PERMISSIONS_USER_PASSWORD = "password";

  private static final String PERMISSIONS_HOST_FIELD = "permissionsHost";
  private static final String PERMISSIONS_HOST = "localhost";

  private static final String PERMISSIONS_PORT_FIELD = "permissionsPort";
  private static final String PERMISSIONS_PORT = "5660";

  private static final UriComponentsBuilder uriComponentsBuilder = UriComponentsBuilder.newInstance()
      .scheme(SCHEME)
      .host(PERMISSIONS_HOST)
      .port(PERMISSIONS_PORT)
      .path("/roles")
      .pathSegment("Notifier")
      .path("/permissions");

  @Mock RestTemplate permissionsMockRestTemplate;

  private PermissionsClient permissionsClient;

  @Before
  public void setUp() throws IllegalAccessException {
    initMocks(this);
    permissionsClient = new PermissionsClient(permissionsMockRestTemplate);
    FieldUtils.writeField(permissionsClient, SCHEME_FIELD, SCHEME, true);
    FieldUtils.writeField(permissionsClient, PERMISSIONS_USER_FIELD, PERMISSIONS_USER, true);
    FieldUtils.writeField(permissionsClient, PERMISSIONS_USER_PASSWORD_FIELD, PERMISSIONS_USER_PASSWORD, true);
    FieldUtils.writeField(permissionsClient, PERMISSIONS_HOST_FIELD, PERMISSIONS_HOST, true);
    FieldUtils.writeField(permissionsClient, PERMISSIONS_PORT_FIELD, PERMISSIONS_PORT, true);

  }

  @Test
  public void correctPermissionsAreReturned() {

    List<String> permissions = Arrays.asList("permission_1", "permission_2", "permission_3");
    ResponseEntity<List<String>> responseEntity = new ResponseEntity<>(permissions, HttpStatus.OK);
    when(permissionsMockRestTemplate.exchange(eq(uriComponentsBuilder.build().encode().toUri()), any(), any(), eq(new ParameterizedTypeReference<List<String>>() {}))).thenReturn(responseEntity);
    List<String> returnedPermissions = permissionsClient.permissionsList("Notifier", "Basic token");

    assertThat(returnedPermissions).hasSize(3);
  }

  @Test
  public void correctPermissionsAreReturnedWithSecurityTokenFeatureSwitch() throws IllegalAccessException {

    FieldUtils.writeField(permissionsClient, "securityTokenFeatureSwitch", true, true);

    List<String> permissions = Arrays.asList("permission_1", "permission_2", "permission_3");
    ResponseEntity<List<String>> responseEntity = new ResponseEntity<>(permissions, HttpStatus.OK);
    when(permissionsMockRestTemplate.exchange(eq(uriComponentsBuilder.build().encode().toUri()), any(), any(), eq(new ParameterizedTypeReference<List<String>>() {}))).thenReturn(responseEntity);
    List<String> returnedPermissions = permissionsClient.permissionsList("Notifier", "Bearer token");

    assertThat(returnedPermissions).hasSize(3);
  }
}
