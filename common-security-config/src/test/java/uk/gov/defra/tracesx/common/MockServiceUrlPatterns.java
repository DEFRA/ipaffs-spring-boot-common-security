package uk.gov.defra.tracesx.common;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import uk.gov.defra.tracesx.common.security.ServiceUrlPatterns;

public class MockServiceUrlPatterns implements ServiceUrlPatterns {

  public static final List<String> PATTERNS = Collections.unmodifiableList(
      Arrays.asList("/path1/*", "/path2/*")
  );

  @Override
  public List<String> getPatterns() {
    return PATTERNS;
  }

  @Override
  public List<String> getBaseUrl() { return Arrays.asList("/path/*"); }
}
