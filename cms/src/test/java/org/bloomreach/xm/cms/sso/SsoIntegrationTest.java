package org.bloomreach.xm.cms.sso;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldap.sdk.LDAPConnection;
import com.unboundid.ldap.sdk.LDAPSearchException;
import com.unboundid.ldap.sdk.SearchResultEntry;
import com.unboundid.ldap.sdk.SearchScope;
import com.unboundid.ldif.LDIFReader;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Full integration test: Keycloak (OIDC) + embedded LDAP.
 *
 * Keycloak stands in for Azure Entra ID — both implement standard OIDC.
 * The test realm is pre-configured with a test user that also exists in the LDAP tree,
 * mirroring the production setup where every SSO user is in LDAP.
 *
 */
@Tag("docker")
@SpringBootTest(
    classes = TestSecurityApplication.class,
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT
)
@ActiveProfiles("test")
@Testcontainers
class SsoIntegrationTest {

  // --- Keycloak container -------------------------------------------------------

  @Container
  static final KeycloakContainer KEYCLOAK = new KeycloakContainer("quay.io/keycloak/keycloak:26.0")
      .withRealmImportFile("keycloak/test-realm.json");

  // --- Embedded LDAP server -----------------------------------------------------

  static InMemoryDirectoryServer LDAP;

  @BeforeAll
  static void startLdap() throws Exception {
    InMemoryDirectoryServerConfig config =
        new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "admin");
    config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("default", 0)); // random port

    LDAP = new InMemoryDirectoryServer(config);

    try (InputStream ldif = SsoIntegrationTest.class.getResourceAsStream("/ldap/test-users.ldif")) {
      LDAP.importFromLDIF(false, new LDIFReader(ldif));
    }

    LDAP.startListening();
  }

  @AfterAll
  static void stopLdap() {
    if (LDAP != null) {
      LDAP.shutDown(true);
    }
  }

  // --- Dynamic properties -------------------------------------------------------

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    // Point the AAD starter at Keycloak's realm — issuer-uri overrides Azure's
    // active-directory-endpoint+tenant-id URL construction entirely.
    String keycloakBase = KEYCLOAK.getAuthServerUrl();
    if (!keycloakBase.endsWith("/")) keycloakBase += "/";
    String keycloakRealmUrl = keycloakBase + "realms/test-realm";
    registry.add("SSO_TENANT_ID", () -> "test-realm");
    registry.add("SSO_APP_ID", () -> "brxm-cms");
    registry.add("SSO_APP_SECRET", () -> "test-secret");
    // Override the issuer URI directly so Keycloak's discovery endpoint is used
    registry.add("spring.security.oauth2.client.provider.azure.issuer-uri", () -> keycloakRealmUrl);

    // LDAP — expose embedded server port for hippo-addon-ldap config
    registry.add("test.ldap.port", () -> LDAP.getListenPort("default"));

    // Enable SSO for all tests in this class
    registry.add("SSO_ENABLED", () -> "true");
  }

  // --- Test fields --------------------------------------------------------------

  @LocalServerPort
  int port;

  @Autowired
  TestRestTemplate restTemplate;

  // --- Security filter chain tests (HTTP level) ---------------------------------

  @Test
  void unprotectedEndpoint_ping_isAccessibleWithoutAuth() {
    ResponseEntity<String> response = restTemplate.getForEntity(
        "http://localhost:" + port + "/ping", String.class);
    // 404 = reached the app; any 4xx other than 401/403 means security passed
    assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.UNAUTHORIZED);
    assertThat(response.getStatusCode()).isNotEqualTo(HttpStatus.FORBIDDEN);
  }

  @Test
  void protectedEndpoint_redirectsUnauthenticatedUser() {
    // Use a non-redirecting client so we can assert the 302 directly.
    // The auto-configured TestRestTemplate follows redirects and ends up at
    // Keycloak's login page (200), which would make the assertion meaningless.
    java.net.http.HttpClient httpClient = java.net.http.HttpClient.newBuilder()
        .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
        .build();
    RestTemplate noRedirect = new RestTemplate(new JdkClientHttpRequestFactory(httpClient));

    ResponseEntity<Void> response = noRedirect.exchange(
        "http://localhost:" + port + "/cms/", HttpMethod.GET, null, Void.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(response.getHeaders().getLocation().toString())
        .contains("/oauth2/authorization/");
  }

  // --- Keycloak wiring checks ---------------------------------------------------

  @Test
  void keycloak_testRealmHasExpectedUser() {
    try (Keycloak admin = Keycloak.getInstance(
        KEYCLOAK.getAuthServerUrl(),
        "master",
        "admin",
        "admin",
        "admin-cli")) {

      var users = admin.realm("test-realm").users().search("alice");
      assertThat(users).hasSize(1);

      UserRepresentation alice = users.get(0);
      assertThat(alice.getUsername()).isEqualTo("alice");
      assertThat(alice.getEmail()).isEqualTo("alice@example.com");
    }
  }

  // --- Embedded LDAP checks -----------------------------------------------------

  @Test
  void ldap_testUserExistsInDirectory() throws LDAPSearchException, Exception {
    try (LDAPConnection conn = new LDAPConnection("localhost", LDAP.getListenPort("default"))) {
      conn.bind("cn=admin,dc=example,dc=com", "admin");

      SearchResultEntry entry = conn.searchForEntry(
          "dc=example,dc=com",
          SearchScope.SUB,
          "(mail=alice@example.com)");

      assertThat(entry).isNotNull();
      assertThat(entry.getAttributeValue("cn")).isEqualTo("Alice Example");
    }
  }

  @Test
  void ldap_usernameMatchesBetweenKeycloakAndLdap() throws Exception {
    // Keycloak's "name" claim (firstName + " " + lastName) must equal the LDAP cn attribute.
    // LoginFilter passes principal.getName() as the brXM username; LdapUserManager looks it
    // up via nameattribute=cn — so these two must be identical for login to succeed.
    try (Keycloak admin = Keycloak.getInstance(
        KEYCLOAK.getAuthServerUrl(), "master", "admin", "admin", "admin-cli")) {

      UserRepresentation alice = admin.realm("test-realm").users().search("alice").get(0);
      String keycloakName = alice.getFirstName() + " " + alice.getLastName();

      try (LDAPConnection conn = new LDAPConnection("localhost", LDAP.getListenPort("default"))) {
        conn.bind("cn=admin,dc=example,dc=com", "admin");
        SearchResultEntry ldapEntry = conn.searchForEntry(
            "dc=example,dc=com", SearchScope.SUB, "(cn=" + keycloakName + ")");

        assertThat(ldapEntry).isNotNull();
        assertThat(ldapEntry.getAttributeValue("cn")).isEqualTo(keycloakName);
      }
    }
  }
}
