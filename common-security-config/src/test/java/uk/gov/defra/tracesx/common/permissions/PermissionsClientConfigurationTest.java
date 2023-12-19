package uk.gov.defra.tracesx.common.permissions;

import static org.junit.Assert.assertEquals;
import static uk.gov.defra.tracesx.common.CommonWebMvcConfiguration.PERMISSIONS_REST_TEMPLATE_QUALIFIER;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestTemplate;

@SpringBootTest(classes = PermissionsClient.class)
@TestPropertySource(properties = {
    "permissions.service.url=https://permissions-local"
})
class PermissionsClientConfigurationTest {

  @MockBean
  @Qualifier(PERMISSIONS_REST_TEMPLATE_QUALIFIER)
  RestTemplate restTemplate;
  @Autowired
  private PermissionsClient permissionsClient;

  @Test
  void should_generate_path() {
    assertEquals("https://permissions-local/roles/test/permissions",
        permissionsClient.getPath("test").build().toUriString());
  }
}
