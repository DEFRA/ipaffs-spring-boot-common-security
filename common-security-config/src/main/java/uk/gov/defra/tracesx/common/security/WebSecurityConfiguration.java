package uk.gov.defra.tracesx.common.security;

import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import uk.gov.defra.tracesx.common.permissions.PermissionsCache;
import uk.gov.defra.tracesx.common.security.filter.JwtTokenFilter;
import uk.gov.defra.tracesx.common.security.filter.PermissionsFilter;
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenValidator;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

   @Autowired
   private JwtTokenValidator jwtTokenValidator;

  @Autowired
  private ServiceUrlPatterns serviceUrlPatterns;

  @Autowired
  private PermissionsCache permissionsCache;


  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
        .authorizeRequests()
        .antMatchers(serviceUrlPatterns.getBaseUrl().toArray(new String[0])).fullyAuthenticated();

    for(String baseUrl : serviceUrlPatterns.getBaseUrl()) {
      http.addFilterBefore(jwtTokenFilter(baseUrl), UsernamePasswordAuthenticationFilter.class);
      http.addFilterBefore(permissionsFilter(baseUrl), UsernamePasswordAuthenticationFilter.class);
    }

    http
        .antMatcher("/**").anonymous();

    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    http.exceptionHandling().authenticationEntryPoint(unauthorizedEntryPoint());
  }

  @Override
  public void configure(WebSecurity web) {
    web.ignoring().antMatchers("/", "/admin", "/admin/*");
  }

  @Bean
  public AuthenticationEntryPoint unauthorizedEntryPoint() {
    return (request, response, authException) -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
  }

  private JwtTokenFilter jwtTokenFilter(String antUrlPattern) {
    return new JwtTokenFilter(antUrlPattern, jwtTokenValidator);
  }

  private PermissionsFilter permissionsFilter(String antUrlPattern) {
    return new PermissionsFilter(antUrlPattern, permissionsCache);
  }

}
