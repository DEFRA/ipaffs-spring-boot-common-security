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
import uk.gov.defra.tracesx.common.security.jwt.JwtTokenFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

  @Autowired
  private JwtTokenFilter jwtTokenFilter;

  @Autowired
  private ServiceUrlPatterns serviceUrlPatterns;

  @Autowired
  private PermissionsFilter permissionsFilter;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable()
        .authorizeRequests()
        .antMatchers(String.join(",", serviceUrlPatterns.getBaseUrl())).authenticated()
        .and()
        .addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class)
        .addFilterBefore(permissionsFilter, UsernamePasswordAuthenticationFilter.class)
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

}
