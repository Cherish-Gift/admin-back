package cherishu.admin.config;

import de.codecentric.boot.admin.server.config.AdminServerProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    private final AdminServerProperties adminServerProperties;

    private static final String[] PUBLIC_WHITELIST = {
        "/assets/**", "/login", "/actuator/**"
    };

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successHandler() {
        var successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setTargetUrlParameter("redirectTo");
        successHandler.setDefaultTargetUrl(adminServerProperties.path("/"));
        return successHandler;
    }

    @Bean
    protected SecurityFilterChain config(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(authorization ->
                authorization.requestMatchers(PUBLIC_WHITELIST)
                    .permitAll()
                    .anyRequest()
                    .authenticated())
            .httpBasic().and()
            .formLogin()
            .loginPage(adminServerProperties.path("/login")).successHandler(successHandler()).and()
            .logout().logoutUrl(adminServerProperties.path("/logout")).and()
            .csrf()
            .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
            .ignoringRequestMatchers(
                adminServerProperties.path("/instances"),
                adminServerProperties.path("/monitor/**")
            ).and()
            .build();
    }
}
