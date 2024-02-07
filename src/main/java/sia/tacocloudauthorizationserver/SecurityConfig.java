package sia.tacocloudauthorizationserver;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.
        HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.
        EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import sia.tacocloudauthorizationserver.Models.UserAuth;
import sia.tacocloudauthorizationserver.Repositories.UserAuthRepository;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authz -> authz
                        .anyRequest().authenticated()
                )
                .formLogin(login -> {})
        ;
        try {
            return http.build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    @Bean
    UserDetailsService userDetailsService(UserAuthRepository userRepo) {
        return username -> userRepo.findByUsername(username);
    }


    @Bean
    public ApplicationRunner dataLoader(
            UserAuthRepository repo,
            PasswordEncoder encoder
    ) {
        if(repo.count() == 0) {
            return args -> {
                repo.save(
                        new UserAuth("habuma", encoder.encode("password"), "ROLE_ADMIN"));
                repo.save(
                        new UserAuth("tacochef", encoder.encode("password"), "ROLE_ADMIN"));
            };
        }
        return args -> {};
    }
}
