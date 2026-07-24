# Authentication API contract

`openapi.json` is the producer-owned contract exported from the running Spring
application. It is the source used by downstream services to review and pin the
Authentication API boundary. Internal environment-data routes are deliberately
excluded.

Normal test runs compare the runtime OpenAPI document with the tracked file.
After an intentional API change, review the change and regenerate it with:

```bash
mvn -B -Dtest=OpenApiExportTest -Dauthentication.updateContract=true test
sha256sum contracts/openapi.json
```

Update `SHA256SUMS` to the reviewed digest in the same pull request. The policy
tests require `GET /api/auth/me`, its `getCurrentUser` operation ID, the
`id`/`name`/`email` response fields, and a single security requirement that
requires both `bearerAuth` and `serviceToken`.
