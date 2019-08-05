# Spring Boot Common Security

## common-security-config

This module should be included as a dependency for Spring projects that use JWT Tokens and Permissions for
security. Included are Spring configuration classes, Servlet Filters used to enforce security policies,
and a client for calling the permissions service.

## common-security-test

This module should be included as a test dependency of the integration tests for any service using
`common-security-config`. It includes two abstract test classes that must be extended to verify security
is working correctly in the service.
