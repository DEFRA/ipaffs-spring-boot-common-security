package uk.gov.defra.tracesx.common.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
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
@EnableMethodSecurity
public class WebSecurityConfiguration {

  private static final int PUBLIC_PATH_SECURITY_ORDER = 1;
  private static final int SERVICE_RESOURCES_SECURITY_ORDER = 2;
  private static final int SERVICE_PATH_SECURITY_ORDER = 3;

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
    @Order(PUBLIC_PATH_SECURITY_ORDER)
    public SecurityFilterChain publicFilterChain(HttpSecurity http) throws Exception {
      http.securityMatcher("/error", "/", "/admin/**")
          .authorizeHttpRequests(authorize ->
              authorize.anyRequest().permitAll())
          .csrf(AbstractHttpConfigurer::disable)
          .sessionManagement(
              sessionManagementConfigurer ->
                sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
          .httpBasic(Customizer.withDefaults());
      return http.build();
    }

    @Bean
    @Order(SERVICE_PATH_SECURITY_ORDER)
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
      http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
        .csrf(AbstractHttpConfigurer::disable)
        .exceptionHandling(
            exception -> exception.authenticationEntryPoint(unauthorizedEntryPoint()))
        .sessionManagement(sessionManagementConfigurer ->
            sessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
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
}
