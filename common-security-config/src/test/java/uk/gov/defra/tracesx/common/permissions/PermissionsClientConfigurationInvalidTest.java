package uk.gov.defra.tracesx.common.permissions;

import static uk.gov.defra.tracesx.common.CommonWebMvcConfiguration.PERMISSIONS_REST_TEMPLATE_QUALIFIER;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

@SpringBootTest(classes = PermissionsClient.class)
class PermissionsClientConfigurationInvalidTest {

  @MockBean
  @Qualifier(PERMISSIONS_REST_TEMPLATE_QUALIFIER)
  RestTemplate restTemplate;
  @Autowired
  private PermissionsClient permissionsClient;

  @Test
  void should_generate_path() {
    try {
        permissionsClient.getPath("test").build();
    } catch (IllegalArgumentException illegalArgumentException) {

      Assertions.assertEquals(
          "Could not resolve permission client placeholder 'permissions.service.port'",
          illegalArgumentException.getMessage());
    }
  }
}
