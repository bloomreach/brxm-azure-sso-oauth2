package org.bloomreach.xm.cms.sso;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;

/**
 * Overrides Azure AD starter beans for local development to redirect the OAuth2 login flow to a
 * local Keycloak instance. Active only when the issuer URI starts with {@code http://}; in
 * production it always starts with {@code https://login.microsoftonline.com/}.
 *
 * <p>Activate by setting {@code SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_AZURE_ISSUER_URI} to the
 * Keycloak realm URL (e.g. from {@code LocalSsoSetupTest}).
 */
@Configuration
@ConditionalOnExpression(
    "'${spring.security.oauth2.client.provider.azure.issuer-uri:https://login}'.startsWith('http://')"
)
class LocalOidcSecurityConfig {

    @Bean
    ClientRegistrationRepository localKeycloakClientRegistrationRepository(
            @Value("${spring.cloud.azure.active-directory.credential.client-id}") String clientId,
            @Value("${spring.cloud.azure.active-directory.credential.client-secret}") String clientSecret,
            @Value("${spring.security.oauth2.client.provider.azure.issuer-uri}") String issuerUri) {

        // OIDC discovery populates all provider metadata from {issuerUri}/.well-known/openid-configuration.
        // Keycloak must be running at startup.
        ClientRegistration registration = ClientRegistrations
                .fromOidcIssuerLocation(issuerUri)
                .registrationId("azure")
                .clientId(clientId)
                .clientSecret(clientSecret)
                .scope("openid", "profile", "email")
                // Production omits {registrationId}; Keycloak accepts this default template via its wildcard redirectUris.
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                // AadOidcUserService defaults to "name" (display name); Keycloak's "name" claim
                // (firstName + lastName) maps to the LDAP cn attribute identically.
                .userNameAttributeName("name")
                .clientName("Local Dev SSO (Keycloak)")
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }

    /**
     * Replaces the Azure AD starter's JWT decoder factory. The Azure factory hard-codes a
     * {@code login.microsoftonline.com} JWK Set URL incompatible with Keycloak; the standard
     * {@link OidcIdTokenDecoderFactory} reads the JWK Set URI from the {@link ClientRegistration}.
     */
    @Bean
    JwtDecoderFactory<ClientRegistration> localJwtDecoderFactory() {
        return new OidcIdTokenDecoderFactory();
    }
}
