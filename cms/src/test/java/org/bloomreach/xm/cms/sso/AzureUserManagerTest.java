package org.bloomreach.xm.cms.sso;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.jcr.SimpleCredentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

class AzureUserManagerTest {

  private final AzureUserManager userManager = new AzureUserManager();

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void authenticate_returnsTrueWhenSsoPrincipalMatchesCredentials() throws Exception {
    OidcUser principal = mock(OidcUser.class);
    when(principal.getName()).thenReturn("alice@example.com");

    Authentication auth = mock(Authentication.class);
    when(auth.getPrincipal()).thenReturn(principal);
    when(auth.isAuthenticated()).thenReturn(true);

    SecurityContextHolder.setContext(new SecurityContextImpl(auth));

    assertTrue(userManager.authenticate(new SimpleCredentials("alice@example.com", "DUMMY".toCharArray())));
  }

  @Test
  void authenticate_returnsFalseWhenUsernameDoesNotMatchCredentials() throws Exception {
    OidcUser principal = mock(OidcUser.class);
    when(principal.getName()).thenReturn("alice@example.com");

    Authentication auth = mock(Authentication.class);
    when(auth.getPrincipal()).thenReturn(principal);
    when(auth.isAuthenticated()).thenReturn(true);

    SecurityContextHolder.setContext(new SecurityContextImpl(auth));

    // credentials are for a different user
    assertFalse(userManager.authenticate(new SimpleCredentials("bob@example.com", "DUMMY".toCharArray())));
  }

  @Test
  void authenticate_returnsFalseWhenNoSecurityContext() throws Exception {
    SecurityContextHolder.clearContext();
    assertFalse(userManager.authenticate(new SimpleCredentials("alice@example.com", "DUMMY".toCharArray())));
  }

  @Test
  void authenticate_returnsFalseWhenAuthenticationIsNotAuthenticated() throws Exception {
    OidcUser principal = mock(OidcUser.class);
    when(principal.getName()).thenReturn("alice@example.com");

    Authentication auth = mock(Authentication.class);
    when(auth.getPrincipal()).thenReturn(principal);
    when(auth.isAuthenticated()).thenReturn(false);

    SecurityContextHolder.setContext(new SecurityContextImpl(auth));

    assertFalse(userManager.authenticate(new SimpleCredentials("alice@example.com", "DUMMY".toCharArray())));
  }
}
