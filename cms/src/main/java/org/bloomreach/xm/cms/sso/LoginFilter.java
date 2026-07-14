package org.bloomreach.xm.cms.sso;

import com.google.common.base.Strings;
import java.io.IOException;
import javax.jcr.SimpleCredentials;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.hippoecm.frontend.model.UserCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Login filter to pick up credentials from Spring and pass them on to the CMS.
 */
public class LoginFilter implements Filter {

  private static final Logger log = LoggerFactory.getLogger(LoginFilter.class);

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
  }

  @Override
  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
    if (servletRequest instanceof HttpServletRequest) {
      HttpServletRequest req = (HttpServletRequest) servletRequest;

      final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      if (!authentication.isAuthenticated()) {
        log.error("User not authenticated");
        filterChain.doFilter(servletRequest, servletResponse);
        return;
      }

      final Object principal = authentication.getPrincipal();
      if (principal instanceof AuthenticatedPrincipal) {
        final String username = ((AuthenticatedPrincipal) principal).getName();
        if (!Strings.isNullOrEmpty(username)) {
          //we don't know the password
          SimpleCredentials credentials = new SimpleCredentials(username, "DUMMY".toCharArray());
          //authenticate via ldaps provider
          credentials.setAttribute("providerId", "ldaps");
          req.setAttribute(UserCredentials.class.getName(), new UserCredentials(credentials));
        }
      }
    }
    filterChain.doFilter(servletRequest, servletResponse);
  }

  @Override
  public void destroy() { }
}
