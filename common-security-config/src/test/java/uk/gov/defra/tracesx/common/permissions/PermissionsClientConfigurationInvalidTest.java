package uk.gov.defra.tracesx.common.permissions;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

import static uk.gov.defra.tracesx.common.CommonWebMvcConfiguration.PERMISSIONS_REST_TEMPLATE_QUALIFIER;

@RunWith(SpringRunner.class)
@SpringBootTest(classes = PermissionsClient.class)
@TestPropertySource(properties = {
        "permissions.security.token-feature-switch=false"
})
public class PermissionsClientConfigurationInvalidTest {
    @Autowired
    private PermissionsClient permissionsClient;

    @MockBean
    @Qualifier(PERMISSIONS_REST_TEMPLATE_QUALIFIER)
    RestTemplate restTemplate;

    @Test(expected = IllegalArgumentException.class)
    public void should_generate_path () {
        permissionsClient.getPath("test").build();
    }
}
