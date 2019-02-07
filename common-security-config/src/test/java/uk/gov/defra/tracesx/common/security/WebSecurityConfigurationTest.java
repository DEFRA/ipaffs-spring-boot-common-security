package uk.gov.defra.tracesx.common.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.test.util.ReflectionTestUtils;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenFilter;

@RunWith(MockitoJUnitRunner.class)
public class WebSecurityConfigurationTest {

  private static final String BASE_URL_MATCHER = "/base/*";
  private static final String AUTHENTICATION_CONFIGURATION = "authenticationConfiguration";
  public static final String JWT_TOKEN_FILTER = "jwtTokenFilter";

  private final WebSecurityConfiguration testee = new WebSecurityConfiguration();

  @Mock
  private ObjectPostProcessor<Object> opp;
  @Mock
  private AuthenticationManager parent;
  @Mock
  private AuthenticationManagerBuilder builder;
  @Mock
  private JwtTokenFilter jwtTokenFilter;
  @Mock
  private AuthenticationConfiguration authenticationConfigurationMock;

  @Test
  public void whenBasicAuthConfigIsCalledReturnsValidConfiguration() throws Exception {

    ReflectionTestUtils
        .setField(testee, AUTHENTICATION_CONFIGURATION, authenticationConfigurationMock);
    ReflectionTestUtils
        .setField(testee, JWT_TOKEN_FILTER, jwtTokenFilter);

    when(authenticationConfigurationMock.getAuthenticationManager()).thenReturn(parent);

    final Map<Class<? extends Object>, Object> sharedObjects = new HashMap<>();
    builder.parentAuthenticationManager(parent);
    builder.build();
    HttpSecurity httpSecurity = new HttpSecurity(opp, builder, sharedObjects);
    testee.configure(httpSecurity);
    final List<ArrayList> urlMappings = (ArrayList) ReflectionTestUtils.getField(
        httpSecurity.getConfigurer(ExpressionUrlAuthorizationConfigurer.class).getRegistry(),
        "urlMappings");

    assertThat(urlMappings.size()).isEqualTo(1);
    assertThat(ReflectionTestUtils
        .getField(ReflectionTestUtils.getField(urlMappings.iterator().next(),"requestMatcher"), "pattern")).isEqualTo(BASE_URL_MATCHER);
  }
}