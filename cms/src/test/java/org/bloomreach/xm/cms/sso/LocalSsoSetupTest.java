package org.bloomreach.xm.cms.sso;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.InMemoryListenerConfig;
import com.unboundid.ldif.LDIFReader;
import dasniko.testcontainers.keycloak.KeycloakContainer;
import java.io.InputStream;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * Developer fixture: starts Keycloak and an embedded LDAP server, then prints
 * the configuration needed to run brXM locally with SSO enabled.
 *
 * This is NOT an automated test — it blocks until you stop it from the IDE.
 * Run it once, apply the printed config to your brXM launch, then test manually.
 *
 * Usage: run this test from your IDE (right-click → Run), then in a separate
 * terminal start brXM: mvn -Pcargo.run -DSSO_ENABLED=true [other vars from output]
 */
@Tag("manual")
class LocalSsoSetupTest {

  static KeycloakContainer KEYCLOAK;
  static InMemoryDirectoryServer LDAP;

  @BeforeAll
  static void start() throws Exception {
    KEYCLOAK = new KeycloakContainer("quay.io/keycloak/keycloak:26.0")
        .withRealmImportFile("keycloak/test-realm.json");
    KEYCLOAK.setPortBindings(List.of("8180:8080"));
    KEYCLOAK.start();

    InMemoryDirectoryServerConfig config =
        new InMemoryDirectoryServerConfig("dc=example,dc=com");
    config.addAdditionalBindCredentials("cn=admin,dc=example,dc=com", "admin");
    config.setListenerConfigs(InMemoryListenerConfig.createLDAPConfig("default", 1389));
    LDAP = new InMemoryDirectoryServer(config);

    try (InputStream ldif = LocalSsoSetupTest.class.getResourceAsStream("/ldap/test-users.ldif")) {
      LDAP.importFromLDIF(false, new LDIFReader(ldif));
    }
    LDAP.startListening();

    printConfig();
  }

  @AfterAll
  static void stop() {
    if (KEYCLOAK != null) KEYCLOAK.stop();
    if (LDAP != null) LDAP.shutDown(true);
  }

  @Test
  void waitForManualTesting() throws InterruptedException {
    System.out.println(">>> Stop the test (IDE stop button or Ctrl+C) to tear down <<<");
    Thread.sleep(Long.MAX_VALUE);
  }

  private static void printConfig() {
    String keycloakUrl = KEYCLOAK.getAuthServerUrl();
    if (!keycloakUrl.endsWith("/")) keycloakUrl += "/";
    String issuerUri = keycloakUrl + "realms/test-realm";
    int ldapPort = LDAP.getListenPort("default");

    System.out.println();
    System.out.println("╔══════════════════════════════════════════════════════════════╗");
    System.out.println("║              SSO Dev Environment Ready                       ║");
    System.out.println("╚══════════════════════════════════════════════════════════════╝");
    System.out.println();
    System.out.println("Keycloak admin console : " + keycloakUrl);
    System.out.println("  Admin credentials    : admin / admin");
    System.out.println("  Test user            : alice@example.com / Password1!");
    System.out.println();
    System.out.println("LDAP                   : ldap://localhost:" + ldapPort + "  (matches ldaps.yaml)");
    System.out.println("  Bind DN              : cn=admin,dc=example,dc=com");
    System.out.println("  Bind password        : admin");
    System.out.println();
    System.out.println("─────────────────────────────────────────────────────────────");
    System.out.println("Start brXM with these environment variables:");
    System.out.println("─────────────────────────────────────────────────────────────");
    System.out.println();
    System.out.println("  SSO_ENABLED=true");
    System.out.println("  SSO_TENANT_ID=test-realm");
    System.out.println("  SSO_APP_ID=brxm-cms");
    System.out.println("  SSO_APP_SECRET=test-secret");
    System.out.println("  SPRING_SECURITY_OAUTH2_CLIENT_PROVIDER_AZURE_ISSUER_URI=" + issuerUri);
    System.out.println("  SSO_LDAP_PRINCIPAL=cn=admin,dc=example,dc=com");
    System.out.println("  SSO_LDAP_CREDENTIALS=admin");
    System.out.println("  SSO_LOGOUT_URL=" + issuerUri + "/protocol/openid-connect/logout");
    System.out.println();
    System.out.println("─────────────────────────────────────────────────────────────");
    System.out.println("ldaps.yaml is already configured for ldap://localhost:1389.");
    System.out.println("Set hippoldap:disabled=false in the repository to enable the");
    System.out.println("LDAP provider for user sync.");
    System.out.println("─────────────────────────────────────────────────────────────");
    System.out.println();
  }
}
