package uk.gov.defra.tracesx.common.security;

public interface PermissionsUrlFilter {
    String getBaseUrlMatcher();
    String getUrlMatcher();
}
