package org.bloomreach.xm.cms.sso;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.jcr.SimpleCredentials;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.hippoecm.frontend.model.UserCredentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

class LoginFilterTest {

  private final LoginFilter filter = new LoginFilter();

  @AfterEach
  void clearSecurityContext() {
    SecurityContextHolder.clearContext();
  }

  @Test
  void doFilter_setsCmsCredentialsWhenSsoPrincipalIsPresent() throws Exception {
    OidcUser principal = mock(OidcUser.class);
    when(principal.getName()).thenReturn("alice@example.com");

    Authentication auth = mock(Authentication.class);
    when(auth.getPrincipal()).thenReturn(principal);
    when(auth.isAuthenticated()).thenReturn(true);

    SecurityContextHolder.setContext(new SecurityContextImpl(auth));

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    FilterChain chain = mock(FilterChain.class);

    filter.doFilter(request, response, chain);

    UserCredentials credentials = (UserCredentials) request.getAttribute(UserCredentials.class.getName());
    SimpleCredentials simpleCredentials = (SimpleCredentials) credentials.getJcrCredentials();
    assertEquals("alice@example.com", simpleCredentials.getUserID());
    assertEquals("ldaps", simpleCredentials.getAttribute("providerId"));

    verify(chain).doFilter(request, response);
  }

  @Test
  void doFilter_doesNotSetCredentialsWhenNoAuthentication() throws Exception {
    SecurityContextHolder.clearContext();

    MockHttpServletRequest request = new MockHttpServletRequest();
    FilterChain chain = mock(FilterChain.class);

    // authentication is null — filter should pass through without setting credentials
    Authentication auth = mock(Authentication.class);
    when(auth.isAuthenticated()).thenReturn(false);
    SecurityContextHolder.setContext(new SecurityContextImpl(auth));

    filter.doFilter(request, new MockHttpServletResponse(), chain);

    assertNull(request.getAttribute(UserCredentials.class.getName()));
  }
}
