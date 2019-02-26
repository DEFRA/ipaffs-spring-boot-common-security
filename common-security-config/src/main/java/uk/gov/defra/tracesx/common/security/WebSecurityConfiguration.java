package uk.gov.defra.tracesx.common.security;

import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

  private static final int PERMISSIONS_ORDER = 2;
  public static final String JWT_TOKEN_FILTER_NAME = "jwtTokenFilter";
  public static final int JWT_TOKEN_FILTER_ORDER = 1;
  private final String PERMISSIONS_FILTER_NAME = "permissionsFilter";

  @Autowired
  private JwtTokenFilter jwtTokenFilter;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/base/*")
        .authenticated()
        .and()
        .exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint())
        .and()
        .csrf()
        .disable();
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
  }

  @Bean
  public AuthenticationEntryPoint unauthorizedEntryPoint() {
    return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }

  @Autowired
  private PermissionsFilter permissionsFilter;

  @Autowired
  private ServiceUrlPatterns serviceUrlPatterns;

  @Bean
  public FilterRegistrationBean jwtTokenFilterRegistration() {
    FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(jwtTokenFilter);
    registration.setUrlPatterns(serviceUrlPatterns.getPatterns());
    registration.setName(JWT_TOKEN_FILTER_NAME);
    registration.setOrder(JWT_TOKEN_FILTER_ORDER);
    return registration;
  }

  @Bean
  public FilterRegistrationBean permissionsFilterRegistration() {
    FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(permissionsFilter);
    registration.setUrlPatterns(serviceUrlPatterns.getPatterns());
    registration.setName(PERMISSIONS_FILTER_NAME);
    registration.setOrder(PERMISSIONS_ORDER);
    return registration;
  }

}
