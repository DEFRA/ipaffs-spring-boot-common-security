package uk.gov.defra.tracesx.common.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import uk.gov.defra.tracesx.common.permissions.PermissionsCache;
import uk.gov.defra.tracesx.common.security.conversation.id.ConversationFilter;
import uk.gov.defra.tracesx.common.security.conversation.id.ConversationStore;
import uk.gov.defra.tracesx.common.security.filter.JwtTokenFilter;
import uk.gov.defra.tracesx.common.security.filter.PermissionsFilter;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration {

  private static final int ERROR_PATH_SECURITY_ORDER = 1;
  private static final int ROOT_PATH_SECURITY_ORDER = 2;
  private static final int ADMIN_PATH_SECURITY_ORDER = 3;
  private static final int SERVICE_RESOURCES_SECURITY_ORDER = 4;

  private void configureForUnsecuredAccess(HttpSecurity http, String pathPattern) throws Exception {
    http.authorizeHttpRequests(authorize -> {
      try {
        authorize
            .requestMatchers(pathPattern).authenticated()
            .and()
            .csrf()
            .disable()
            .sessionManagement()
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });
  }

  @Configuration
  @Order(SERVICE_RESOURCES_SECURITY_ORDER)
  public static class ServiceResourcesSecurityConfiguration {

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

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
      return http.build();
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

  @Configuration
  @Order(ERROR_PATH_SECURITY_ORDER)
  public class ErrorSecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      configureForUnsecuredAccess(http, "/error");
      return http.build();
    }
  }

  @Configuration
  @Order(ROOT_PATH_SECURITY_ORDER)
  public class RootSecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      configureForUnsecuredAccess(http, "/");
      return http.build();
    }
  }

  @Configuration
  @Order(ADMIN_PATH_SECURITY_ORDER)
  public class AdminSecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      configureForUnsecuredAccess(http, "/admin/**");
      return http.build();
    }
  }
}
