package uk.gov.defra.tracesx.common.security;

import java.util.List;

public interface ServiceUrlPatterns {
  /**
   * @return a list of patterns that require authorization to be applied by the.
   * @see uk.gov.defra.tracesx.common.security.PreAuthorizeChecker
   */
  List<String> getAuthorizedPatterns();
}
