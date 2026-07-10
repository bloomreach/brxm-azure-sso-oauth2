package org.bloomreach.xm.cms.sso;

import static org.bloomreach.xm.cms.sso.SsoConstants.LOCAL_LOGIN_ENABLED;
import static org.bloomreach.xm.cms.sso.SsoConstants.LOCAL_LOGIN_HEADER;

import com.azure.spring.cloud.autoconfigure.implementation.aad.security.AadWebApplicationHttpSecurityConfigurer;
import java.io.IOException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

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

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http.with(AadWebApplicationHttpSecurityConfigurer.aadWebApplication(), Customizer.withDefaults());

    //check if SSO is enabled
    if (ssoEnabled) {
      log.info("SSO is enabled - securing CMS endpoints.");
      http.authorizeHttpRequests(authorize -> authorize
          //utility servlets/endpoints are not secured, they have their own internal auth
          .requestMatchers(
              "/ws/indexexport", "/ping",
              "/repository/**",
              "/angular/**", "/skin/**", "/ckeditor/**", "/**.svg",
              "/logging/**",
              "/ws/**",
              SsoConstants.LOGOUT_URL) //used by Azure for logging out
          .permitAll()
          //allow local login via request headers
          .requestMatchers(new RequestHeaderRequestMatcher(LOCAL_LOGIN_HEADER, LOCAL_LOGIN_ENABLED)).permitAll()
          //everyting else is secured
          .anyRequest().authenticated());
      http.addFilterAfter(new LoginFilter(), AuthorizationFilter.class);

      //logout handler to forward user to Azure's logout page
      http.logout(logout -> logout.logoutSuccessHandler(new LogoutSuccessHandler() {
        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
          boolean localLogin = request.getHeader(LOCAL_LOGIN_HEADER) != null
              && request.getHeader(LOCAL_LOGIN_HEADER).equalsIgnoreCase(LOCAL_LOGIN_ENABLED);
          if (!localLogin) {
            //the JSP uses Javascript to break out of the iframing done by the navapp
            String url = "https://login.microsoftonline.com/" + System.getenv("SSO_TENANT_ID") + "/oauth2/v2.0/logout";
            request.setAttribute("logoutUrl", url);
            request.getRequestDispatcher(SsoConstants.LOGOUT_JSP).forward(request, response);
            response.flushBuffer();
          }
        }
      }));
    } else {
      log.info("SSO is disabled.");
      http.authorizeHttpRequests(authorize -> authorize
          .anyRequest().permitAll());
    }

    //CSRF not supported by CMS
    http.csrf(AbstractHttpConfigurer::disable);
    //same origin needed by CMS
    http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

    return http.build();
  }
}
