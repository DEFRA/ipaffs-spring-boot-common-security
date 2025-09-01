# Spring Boot Common Security

| :warning: DEPRECATED           |
|:----------------------------|
| This library is no longer used - it is replaced by  the `security` and `security-tests` modules in the `spring-boot-common` repo |

## common-security-config

This module should be included as a dependency for Spring projects that use JWT Tokens and Permissions for
security. Included are Spring configuration classes, Servlet Filters used to enforce security policies,
and a client for calling the permissions service.

## common-security-test

This module should be included as a test dependency of the integration tests for any service using
`common-security-config`. It includes two abstract test classes that must be extended to verify security
is working correctly in the service.

## Secret scanning
Secret scanning is setup using [truffleHog](https://github.com/trufflesecurity/truffleHog).
It is used as a pre-push hook and will scan any local commits being pushed

### Pre-push hook setup
1. Install [truffleHog](https://github.com/trufflesecurity/truffleHog)
    - `brew install trufflesecurity/trufflehog/trufflehog`
2. Set DEFRA_WORKSPACE env var (`export DEFRA_WORKSPACE=/path/to/workspace`)
3. Potentially there's an older version of Trufflehog located at: `/usr/local/bin/trufflehog`. If so, remove this.

### Git hook setup

1. Run `mvn install` to configure hooks from service folder.
