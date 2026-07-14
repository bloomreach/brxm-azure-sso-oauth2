# Azure Entra ID SSO for BloomReach XM 16

SSO integration using Azure AD OAuth2 with LDAP-backed user management. Toggled via the `SSO_ENABLED` environment variable.

## Authentication Flow

1. User hits CMS → Spring Security redirects to Azure AD
2. Azure AD authenticates → redirects back with OAuth2 token
3. `LoginFilter` extracts the principal, creates JCR credentials with `providerId=ldaps`
4. `AzureUserManager` validates the Spring Security principal matches → authenticates
5. CMS loads roles/groups from LDAP

## Classes

### [SecurityConfig](cms/src/main/java/org/bloomreach/xm/cms/sso/SecurityConfig.java)
Spring Security configuration. When SSO is enabled, secures all CMS endpoints except utility paths (`/ping`, `/ws/**`, static assets). Supports local login bypass via `x-local-login` header. Uses `SsoAadConfigurer` (a subclass of `AadWebApplicationHttpSecurityConfigurer`) to wire the logout handler — a direct `http.logout()` call does not work because `AadWebApplicationHttpSecurityConfigurer.init()` overwrites it during `http.build()`.

### [LoginFilter](cms/src/main/java/org/bloomreach/xm/cms/sso/LoginFilter.java)
Servlet filter that bridges Spring Security to the CMS. Extracts the authenticated principal from `SecurityContextHolder` and sets `UserCredentials` on the request with a dummy password and `providerId=ldaps`.

### [AzureUserManager](cms/src/main/java/org/bloomreach/xm/cms/sso/AzureUserManager.java)
Extends `LdapUserManager`. Authenticates users by matching the Spring Security principal against the provided credentials. Direct LDAP password authentication is disabled.

### [CustomLdapSecurityProvider](cms/src/main/java/org/bloomreach/xm/cms/sso/CustomLdapSecurityProvider.java)
Extends `LdapSecurityProvider`. Reads LDAP bind credentials from environment variables instead of storing them directly in the JCR repository. Uses `CredentialsProvider` for extraction.

### [CustomSyncJob](cms/src/main/java/org/bloomreach/xm/cms/sso/CustomSyncJob.java)
Extends `LdapSecurityProvider.SyncJob`. Same env-var credential resolution as `CustomLdapSecurityProvider` for the LDAP sync process.

### [CredentialsProvider](cms/src/main/java/org/bloomreach/xm/cms/sso/CredentialsProvider.java)
Interface with a default method that resolves LDAP principal/password from environment variable names stored in JCR node properties.

### [LogoutService](cms/src/main/java/org/bloomreach/xm/cms/sso/LogoutService.java)
Extends `CmsLogoutService`. Redirects to `/logout` after CMS-internal logout, triggering Spring Security's logout filter. The IdP logout URL is configured via `sso.logout-url` and served to the browser via a JSP that breaks out of the navapp iframe before redirecting.

### [SsoConstants](cms/src/main/java/org/bloomreach/xm/cms/sso/SsoConstants.java)
Shared constants: `SSO_ENABLED`, logout URL/JSP path, and local login header name/value.

## Configuration

### [application.yaml](cms/src/main/resources/application.yaml)
Spring Boot configuration for the Azure AD integration. Binds `SSO_TENANT_ID`, `SSO_APP_ID`, and `SSO_APP_SECRET` to the Azure Active Directory Spring Cloud starter. Sets the CMS servlet context path to `/cms` and enables framework-level forwarded header handling. The IdP logout URL is configured via `sso.logout-url` (overridable with `SSO_LOGOUT_URL`).

## Environment Variables

| Variable | Description |
|---|---|
| `SSO_ENABLED` | Set to `true` to enable SSO |
| `SSO_TENANT_ID` | Azure AD tenant ID |
| `SSO_APP_ID` | Azure AD application (client) ID |
| `SSO_APP_SECRET` | Azure AD client secret |
| `SSO_LDAP_PRINCIPAL` | LDAP bind DN |
| `SSO_LDAP_CREDENTIALS` | LDAP bind password |
| `SSO_LOGOUT_URL` | IdP logout URL (defaults to the Azure AD v2.0 logout endpoint for `SSO_TENANT_ID`) |

## Local SSO Development

Two Maven profiles in the `cms` module support SSO testing. Both are excluded from the default `mvn test` run.

### `local-sso` profile — manual dev fixture

```
mvn test -Plocal-sso
```

Runs `LocalSsoSetupTest` (`@Tag("manual")`). Starts a Keycloak container on port 8180 and an embedded LDAP server on port 1389, then prints all the environment variables needed to launch brXM with SSO enabled. The test blocks until stopped from the IDE or with Ctrl+C, keeping the infrastructure live while you test manually.

```
mvn -Pcargo.run -DSSO_ENABLED=true \
    -DSSO_TENANT_ID=test-realm \
    -DSSO_APP_ID=brxm-cms \
    -DSSO_APP_SECRET=test-secret \
    -DSPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_AZURE_ISSUER_URI=http://localhost:8180/realms/test-realm \
    -DSSO_LDAP_PRINCIPAL=cn=admin,dc=example,dc=com \
    -DSSO_LDAP_CREDENTIALS=admin \
    -DSSO_LOGOUT_URL=http://localhost:8180/realms/test-realm/protocol/openid-connect/logout
```

Test user: `alice@example.com` / `Password1!`. Keycloak admin console at `http://localhost:8180` (admin/admin).

### `docker-tests` profile — automated integration tests

```
mvn test -Pdocker-tests
```

Runs `SsoIntegrationTest` (`@Tag("docker")`). Requires Docker. Starts Keycloak via Testcontainers on a random port alongside an embedded LDAP server and verifies the Spring Security filter chain rules against a real OIDC provider.

## Upgrade notes (v15 → v16)

Spring Cloud Azure upgraded from 4.x to 6.x. The `AadWebSecurityConfigurerAdapter` extension pattern is replaced by `AadWebApplicationHttpSecurityConfigurer` registered via `http.with()`. Spring Security 6 now filters all servlet dispatcher types (including `FORWARD`) by default, which required explicitly permitting forward dispatches so the logout JSP redirect is not blocked by the authorization filter.
