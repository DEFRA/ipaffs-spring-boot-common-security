# common-security-config

Services using JWT Token + Permissions security should depend on this module. To activate it
this module's classes much be in the component scan path. Including the 
`@ComponentScan({"uk.gov.defra.tracesx"})` is sufficient for Spring to pick up the shared settings
defined by this module.

Services using this module also need to implement one interface: `ServiceUrlPatterns` This interface
defines which paths require security. Ensure the implementing class is annotated `@Component` so that
it can be injected as needed.

## Application Properties

The following properties can be defined in the consuming application `application.yml`.
All properties are **required** unless otherwise specified.

* `spring.security.jwt.jwks`: Comma-separated list of jwks urls
* `spring.security.jwt.iss`: Comma-separated list of expected issuers, one per jwks url in the same order
* `spring.security.jwt.aud`: Comma-separated list of expected audiences, one per jwks url in the same order
* `info.app.name`: The standard place where we specify the name of the application

The following properties relate to API requests made to the permissions microservice.
* `permissions.service.scheme`
* `permissions.service.host`
* `permissions.service.port`
* `permissions.service.user`
* `permissions.service.password`
* `permissions.security.token-feature-switch`
* `permissions.service.connectionTimeout`: Optional, default 25
* `permissions.service.readTimeout`: Optional, default 25