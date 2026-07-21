# Service identity boundary

Authentication-service is not a browser API. User-management-gateway is its
approved caller and adds `X-Service-Token` from runtime secret configuration to
every `/api/auth/**` request. Authentication-service compares the complete value
in constant time and never logs, returns, stores in the database, or uses it as
a metric label. Missing, duplicate and invalid values receive the same stable
response.

Environment-data tooling has a separate `X-Environment-Data-Token`. It grants
no access to auth routes and the general service identity grants no access to
environment-data routes. Valid tooling identity does not bypass the existing
fail-closed environment/profile guard; production remains forbidden.

Only `/actuator/health` is public. Unknown routes, API documentation and every
other management/application route are denied by the security chain. Production
also disables H2, OpenAPI, Swagger UI and detailed health in configuration.

Generate independent high-entropy values of at least 32 random bytes and supply
them through the deployment secret manager. Never put them in a URL, browser
bundle, request log, command line, repository, issue or support transcript.
Rotate the gateway token in compatibility order. This release accepts one value,
so a no-downtime rotation needs a later approved overlap design; otherwise use a
coordinated gateway/authentication-service restart and verify health plus a
registration/login/profile smoke path. The environment-data identity is rotated
independently and must remain unavailable to production workloads.
