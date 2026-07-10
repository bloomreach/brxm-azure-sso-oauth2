package org.bloomreach.xm.cms.sso;

import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

/**
 * Minimal Spring Boot application for security tests.
 * Component scan is scoped to this package, which contains only SecurityConfig —
 * the full brXM CMS stack (Wicket, JCR, etc.) is not loaded.
 */
@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public class TestSecurityApplication {
}
