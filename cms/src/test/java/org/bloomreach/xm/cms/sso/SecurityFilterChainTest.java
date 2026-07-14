package org.bloomreach.xm.cms.sso;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Tests the SecurityFilterChain rules (permit/deny) without a real OAuth2 provider.
 * Uses Spring Security's mockOidcLogin() to inject a pre-authenticated OIDC user,
 * bypassing the actual authorization code flow.
 *
 * Two nested contexts are used — one with SSO enabled and one disabled — because
 * SecurityConfig builds the filter chain once at startup based on the SSO_ENABLED property.
 */
@SpringBootTest(
    classes = TestSecurityApplication.class,
    webEnvironment = SpringBootTest.WebEnvironment.MOCK
)
@ActiveProfiles("test")
class SecurityFilterChainTest {

  // ─── SSO enabled ────────────────────────────────────────────────────────────

  @Nested
  @TestPropertySource(properties = "SSO_ENABLED=true")
  class WhenSsoEnabled {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
      mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void permittedEndpoints_areAccessibleWithoutAuth() throws Exception {
      // 404 = passed through security with no application handler — not blocked by 401/302
      mockMvc.perform(get("/ping")).andExpect(status().isNotFound());
      mockMvc.perform(get("/ws/indexexport")).andExpect(status().isNotFound());
      mockMvc.perform(get("/repository/")).andExpect(status().isNotFound());
      mockMvc.perform(get("/angular/app.js")).andExpect(status().isNotFound());
    }

    @Test
    void logoutEndpoint_isHandledWithoutAccessDenied() throws Exception {
      // /logout is permitted but intercepted by Spring Security's LogoutFilter (CSRF-disabled
      // mode processes GET too), which invokes the LogoutSuccessHandler — expect a redirect,
      // not a 401/403.
      mockMvc.perform(get("/logout"))
          .andExpect(status().is(org.hamcrest.Matchers.not(org.hamcrest.Matchers.equalTo(401))))
          .andExpect(status().is(org.hamcrest.Matchers.not(org.hamcrest.Matchers.equalTo(403))));
    }

    @Test
    void protectedEndpoint_redirectsUnauthenticatedUserToLogin() throws Exception {
      mockMvc.perform(get("/cms/"))
          .andExpect(status().is3xxRedirection())
          .andExpect(redirectedUrlPattern("**/oauth2/authorization/**"));
    }

    @Test
    void protectedEndpoint_isAccessibleWithOidcLogin() throws Exception {
      mockMvc.perform(get("/cms/")
              .with(oidcLogin()
                  .idToken(token -> token.claim("preferred_username", "alice@example.com"))))
          .andExpect(status().isNotFound()); // 404 = reached the app, not blocked by security
    }

    @Test
    void localLoginHeader_bypassesOauth2ForProtectedEndpoint() throws Exception {
      mockMvc.perform(get("/cms/")
              .header(SsoConstants.LOCAL_LOGIN_HEADER, SsoConstants.LOCAL_LOGIN_ENABLED))
          .andExpect(status().isNotFound()); // permitted via request header matcher
    }
  }

  // ─── SSO disabled ───────────────────────────────────────────────────────────

  @Nested
  @TestPropertySource(properties = "SSO_ENABLED=false")
  class WhenSsoDisabled {

    @Autowired
    private WebApplicationContext context;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
      mockMvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Test
    void anyRequest_isPermittedWithoutAuth() throws Exception {
      // When SSO is off, anyRequest().permitAll() is configured — everything passes through
      mockMvc.perform(get("/ping")).andExpect(status().isNotFound());
      mockMvc.perform(get("/cms/")).andExpect(status().isNotFound());
      mockMvc.perform(get("/repository/")).andExpect(status().isNotFound());
      mockMvc.perform(get("/ws/indexexport")).andExpect(status().isNotFound());
    }

    @Test
    void protectedEndpoint_doesNotRedirectToOauth2Login() throws Exception {
      // No OAuth2 redirect when SSO is disabled — unauthenticated request passes straight through
      mockMvc.perform(get("/cms/"))
          .andExpect(status().isNotFound());
    }

    @Test
    void protectedEndpoint_isAccessibleWithOrWithoutOidcLogin() throws Exception {
      // With SSO off, an already-authenticated user is also unblocked
      mockMvc.perform(get("/cms/")
              .with(oidcLogin()
                  .idToken(token -> token.claim("preferred_username", "alice@example.com"))))
          .andExpect(status().isNotFound());
    }
  }
}
