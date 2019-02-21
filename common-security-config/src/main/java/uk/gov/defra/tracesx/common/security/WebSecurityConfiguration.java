package uk.gov.defra.tracesx.common.security;

import static java.util.Arrays.asList;

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
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

  private final int PERMISSIONS_ORDER = 1;
  private final String PERMISSIONS_AUTH_FILTER = "authFilter";

  @Autowired
  private JwtTokenFilter jwtTokenFilter;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.authorizeRequests()
        .antMatchers("/base/*")
        .authenticated()
        .and()
        .addFilterAfter(jwtTokenFilter, SecurityContextPersistenceFilter.class)
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

  @Bean
  public FilterRegistrationBean countriesAuthFilterRegistration() {
    FilterRegistrationBean result = new FilterRegistrationBean();
    result.setFilter(permissionsFilter);
    result.setUrlPatterns(asList(COUNTRIES_URL_MATCHER, BASE_URL_MATCHER));
    result.setName(PERMISSIONS_AUTH_FILTER);
    result.setOrder(PERMISSIONS_ORDER);
    return result;
  }

}
