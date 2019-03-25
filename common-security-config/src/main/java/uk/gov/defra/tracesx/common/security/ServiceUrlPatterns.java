package uk.gov.defra.tracesx.common.security;

import java.util.Collection;
import java.util.List;

public interface ServiceUrlPatterns {
  /**
   * @return a list of patterns matching the urls used by this endpoint
   * @see org.springframework.boot.web.servlet.FilterRegistrationBean#setUrlPatterns(Collection)
   */
  List<String> getPatterns();

  List<String> getBaseUrl();
}
