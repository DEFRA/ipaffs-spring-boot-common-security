package uk.gov.defra.tracesx.common.permissions;

import static java.lang.Boolean.TRUE;
import static java.util.Collections.EMPTY_LIST;
import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpStatus.OK;

import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

@RunWith(MockitoJUnitRunner.class)
public class PermissionsClientTest {

  private static final String USER = "testUser";
  private static final String PASSWORD = "testPassword";
  private static final String READ = "read";
  private static final String ROLE = "importer";
  private static final String TOKEN = "dummyToken";
  private static final String INVALID_ROLE = "invalid.role";
  private static final String URL = "https://permissions-local";
  private static final String PERMISSIONS_URL = "permissionsUrl";
  private static final String PERMISSIONS_USER = "permissionsUser";
  private static final String PERMISSIONS_PASSWORD = "permissionsPassword";
  private static final String SECURITY_TOKEN_FEATURE_SWITCH = "securityTokenFeatureSwitch";
  private final List<String> perms = singletonList(READ);

  @Mock private RestTemplate restTemplate;
  @InjectMocks private PermissionsClient permissionsService;

  @Before
  public void setup() {
    ReflectionTestUtils.setField(permissionsService, PERMISSIONS_USER, USER);
    ReflectionTestUtils.setField(permissionsService, PERMISSIONS_PASSWORD, PASSWORD);
    ReflectionTestUtils.setField(permissionsService, SECURITY_TOKEN_FEATURE_SWITCH, TRUE);
    ReflectionTestUtils.setField(permissionsService, PERMISSIONS_URL, URL);

    final ResponseEntity<List<String>> responseEntity = createResponseEntity();
    when(restTemplate.exchange(
            any(),
            eq(GET),
            any(HttpEntity.class),
            eq(new ParameterizedTypeReference<List<String>>() {})))
        .thenReturn(responseEntity);
  }

  @Test
  public void testWhenPermissionsListIsCalledThenReturnListOfPermissions() {

    final List<String> permissionsList = permissionsService.permissionsList(ROLE, TOKEN);

    assertThat(permissionsList).hasSize(1);
    assertThat(permissionsList.get(0)).isEqualTo(READ);
  }

  @Test
  public void testWhenPermissionsCalledWithInvalidRoleThenReturnEmptyList() {

    when(restTemplate.exchange(
            any(),
            eq(GET),
            any(HttpEntity.class),
            eq(new ParameterizedTypeReference<List<String>>() {})))
        .thenReturn(new ResponseEntity<>(EMPTY_LIST, OK));

    final List<String> permissionsList = permissionsService.permissionsList(INVALID_ROLE, TOKEN);

    assertThat(permissionsList).hasSize(0);
  }

  private ResponseEntity<List<String>> createResponseEntity() {
    return new ResponseEntity<>(perms, OK);
  }
}
