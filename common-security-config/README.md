# common-security-config

Services using JWT Token + Permissions security should depend on this module. To activate it
this module's classes much be in the component scan path. Including the 
`@ComponentScan({"uk.gov.defra.tracesx"})` is sufficient for Spring to pick up the shared settings
defined by this module.

Service using this module also need to implement one interface: `ServiceUrlPatterns` This interface
defines which paths require security. Ensure the implementing class is annotated `@Component` so that
it can be injected as needed.