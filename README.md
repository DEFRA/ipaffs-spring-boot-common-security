# Spring Boot Common Security

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
    - `brew install go`
    - `git clone https://github.com/trufflesecurity/trufflehog.git`
    - `cd trufflehog; go install`
2. Set DEFRA_WORKSPACE env var (`export DEFRA_WORKSPACE=/path/to/workspace`)
3. Potentially there's an older version of Trufflehog located at: `/usr/local/bin/trufflehog`. If so, remove this.
4. Create a symlink: `ln -s ~/go/bin/truffleHog /usr/local/bin/trufflehog`
5. From this project root directory copy the pre-push hook: `cp hooks/pre-push .git/hooks/pre-push`
6. If you don't see trufflehog running upon pushing or see a warning that looks like `The '.git/hooks/pre-push' hook was ignored because it's not set as executable.`, make the hook file executable by running `chmod +x .git/hooks/pre-push`.
