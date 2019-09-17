package uk.gov.defra.tracesx.common.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import uk.gov.defra.tracesx.common.permissions.PermissionsCache;
import uk.gov.defra.tracesx.common.security.conversation.id.ConversationFilter;
import uk.gov.defra.tracesx.common.security.conversation.id.ConversationStore;
import uk.gov.defra.tracesx.common.security.filter.JwtTokenFilter;
import uk.gov.defra.tracesx.common.security.filter.PermissionsFilter;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration {
  private static final int ERROR_PATH_SECURITY_ORDER = 1;
  private static final int ROOT_PATH_SECURITY_ORDER = 2;
  private static final int ADMIN_PATH_SECURITY_ORDER = 3;
  private static final int SERVICE_RESOURCES_SECURITY_ORDER = 4;

  private void configureForUnsecuredAccess(HttpSecurity http, String pathPattern) throws Exception {
    http.antMatcher(pathPattern)
        .authorizeRequests()
        .anyRequest()
        .permitAll()
        .and()
        .csrf()
        .disable()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
  }

  @Configuration
  @Order(ERROR_PATH_SECURITY_ORDER)
  public class ErrorSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      configureForUnsecuredAccess(http, "/error");
    }
  }

  @Configuration
  @Order(ROOT_PATH_SECURITY_ORDER)
  public class RootSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      configureForUnsecuredAccess(http, "/");
    }
  }

  @Configuration
  @Order(ADMIN_PATH_SECURITY_ORDER)
  public class AdminSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      configureForUnsecuredAccess(http, "/admin/**");
    }
  }

  @Configuration
  @Order(SERVICE_RESOURCES_SECURITY_ORDER)
  public static class ServiceResourcesSecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final JwtTokenValidator jwtTokenValidator;
    private final PermissionsCache permissionsCache;
    private final ConversationStore conversationStore;

    public ServiceResourcesSecurityConfiguration(
        JwtTokenValidator jwtTokenValidator,
        PermissionsCache permissionsCache,
        ConversationStore conversationStore) {
      super();
      this.jwtTokenValidator = jwtTokenValidator;
      this.permissionsCache = permissionsCache;
      this.conversationStore = conversationStore;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
      http.csrf()
          .disable()
          .exceptionHandling()
          .authenticationEntryPoint(unauthorizedEntryPoint())
          .and()
          .sessionManagement()
          .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
          .and()
          .authorizeRequests()
          .anyRequest()
          .fullyAuthenticated()
          .and()
          .addFilterBefore(conversationFilter(), UsernamePasswordAuthenticationFilter.class)
          .addFilterBefore(jwtTokenFilter(), UsernamePasswordAuthenticationFilter.class)
          .addFilterBefore(permissionsFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public AuthenticationEntryPoint unauthorizedEntryPoint() {
      return (request, response, authException) ->
          response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
    }

    private ConversationFilter conversationFilter() {
      return new ConversationFilter(conversationStore);
    }

    private JwtTokenFilter jwtTokenFilter() {
      return new JwtTokenFilter(AnyRequestMatcher.INSTANCE, jwtTokenValidator);
    }

    private PermissionsFilter permissionsFilter() {
      return new PermissionsFilter(AnyRequestMatcher.INSTANCE, permissionsCache);
    }
  }
}
