package org.bloomreach.xm.cms.sso;

import com.azure.spring.cloud.autoconfigure.implementation.aad.security.AadWebApplicationHttpSecurityConfigurer;
import jakarta.servlet.DispatcherType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

import static org.bloomreach.xm.cms.sso.SsoConstants.LOCAL_LOGIN_ENABLED;
import static org.bloomreach.xm.cms.sso.SsoConstants.LOCAL_LOGIN_HEADER;

/**
 * Security configuration to place desired endpoints behind auth.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

  @Value("${SSO_ENABLED:false}")
  private boolean ssoEnabled;

  @Value("${sso.logout-url}")
  private String ssoLogoutUrl;

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    // AadWebApplicationHttpSecurityConfigurer.init() overwrites any LogoutSuccessHandler set via
    // http.logout() because init() runs during http.build(), after filterChain() returns.
    // SsoAadConfigurer overrides oidcLogoutSuccessHandler() — the virtual method init() calls —
    // so our handler is installed directly rather than being overwritten afterward.
    if (ssoEnabled) {
      log.info("SSO is enabled - securing CMS endpoints.");
      http.with(new SsoAadConfigurer(ssoLogoutUrl), Customizer.withDefaults());
      http.authorizeHttpRequests(authorize -> authorize
          // Spring Security 6 checks all dispatcher types including FORWARD by default.
          // Server-side forwards (e.g. to logout-redirect.jsp) are internal and need no auth check.
          .dispatcherTypeMatchers(DispatcherType.FORWARD).permitAll()
          //utility servlets/endpoints are not secured, they have their own internal auth
          .requestMatchers(
              "/ws/indexexport", "/ping",
              "/repository/**",
              "/angular/**", "/skin/**", "/ckeditor/**", "/**.svg",
              "/logging/**",
              "/ws/**",
              SsoConstants.LOGOUT_URL)
          .permitAll()
          //allow local login via request headers
          .requestMatchers(new RequestHeaderRequestMatcher(LOCAL_LOGIN_HEADER, LOCAL_LOGIN_ENABLED)).permitAll()
          //everything else is secured
          .anyRequest().authenticated());
      http.addFilterAfter(new LoginFilter(), AuthorizationFilter.class);
    } else {
      log.info("SSO is disabled.");
      http.with(AadWebApplicationHttpSecurityConfigurer.aadWebApplication(), Customizer.withDefaults());
      http.authorizeHttpRequests(authorize -> authorize
          .anyRequest().permitAll());
    }

    //CSRF not supported by CMS
    http.csrf(AbstractHttpConfigurer::disable);
    //same origin needed by CMS
    http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

    return http.build();
  }

  // Subclasses AadWebApplicationHttpSecurityConfigurer so our LogoutSuccessHandler is installed
  // by init() itself rather than being overwritten by it.
  private static class SsoAadConfigurer extends AadWebApplicationHttpSecurityConfigurer {
    private final String ssoLogoutUrl;

    SsoAadConfigurer(String ssoLogoutUrl) {
      this.ssoLogoutUrl = ssoLogoutUrl;
    }

    @Override
    protected LogoutSuccessHandler oidcLogoutSuccessHandler() {
      return (request, response, authentication) -> {
        boolean localLogin = request.getHeader(LOCAL_LOGIN_HEADER) != null
            && request.getHeader(LOCAL_LOGIN_HEADER).equalsIgnoreCase(LOCAL_LOGIN_ENABLED);
        if (!localLogin) {
          //the JSP uses Javascript to break out of the iframing done by the navapp
          request.setAttribute("logoutUrl", ssoLogoutUrl);
          request.getRequestDispatcher(SsoConstants.LOGOUT_JSP).forward(request, response);
          response.flushBuffer();
        }
      };
    }
  }
}
