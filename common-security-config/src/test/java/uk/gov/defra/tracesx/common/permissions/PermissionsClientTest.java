package uk.gov.defra.tracesx.common.permissions;

import static java.util.Collections.singletonList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpStatus.OK;

import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

@ExtendWith(MockitoExtension.class)
class PermissionsClientTest{

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
  private final List<String> perms = singletonList(READ);

  @Mock
  private RestTemplate restTemplate;
  @InjectMocks
  private PermissionsClient permissionsService;

  @BeforeEach
  public void setup() {
    ReflectionTestUtils.setField(permissionsService, PERMISSIONS_USER, USER);
    ReflectionTestUtils.setField(permissionsService, PERMISSIONS_PASSWORD, PASSWORD);
    ReflectionTestUtils.setField(permissionsService, PERMISSIONS_URL, URL);

    final ResponseEntity<List<String>> responseEntity = createResponseEntity();

    lenient().when(restTemplate.exchange(
        any(),
        eq(GET),
        any(HttpEntity.class),
        eq(new ParameterizedTypeReference<List<String>>() {
        })))
        .thenReturn(responseEntity);
  }

  @Test
   void testWhenPermissionsListIsCalledThenReturnListOfPermissions() {

    final List<String> permissionsList = permissionsService.permissionsList(ROLE, TOKEN);

    assertThat(permissionsList).hasSize(1);
    assertThat(permissionsList.get(0)).isEqualTo(READ);
  }

  @Test
   void testWhenPermissionsCalledWithInvalidRoleThenReturnEmptyList() {

    when(restTemplate.exchange(
        any(),
        eq(GET),
        any(HttpEntity.class),
        eq(new ParameterizedTypeReference<List<String>>() {
        })))
        .thenReturn(new ResponseEntity<>(Collections.emptyList(), OK));

    final List<String> permissionsList = permissionsService.permissionsList(INVALID_ROLE, TOKEN);

    assertThat(permissionsList).isEmpty();
  }

  @Test
   void testGetPermissions_ThrowsCustomException_WhenResourceAccessExceptionThrown() {

    when(restTemplate.exchange(
        any(),
        eq(GET),
        any(HttpEntity.class),
        eq(new ParameterizedTypeReference<List<String>>() {
        })))
        .thenThrow(new ResourceAccessException("test"));

    assertThatThrownBy(() -> permissionsService.permissionsList(INVALID_ROLE, TOKEN))
        .isInstanceOf(ResourceAccessException.class)
        .hasMessageContaining("Unable to get permissions due to exception: ");
  }

  private ResponseEntity<List<String>> createResponseEntity() {
    return new ResponseEntity<>(perms, OK);
  }
}
