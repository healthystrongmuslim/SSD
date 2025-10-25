package edu.nu.owaspapivulnlab.config;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DataSeeder {

    @Bean
    CommandLineRunner seed(AppUserRepository users,
                           AccountRepository accounts,
                           PasswordEncoder passwordEncoder) {
        return args -> {

            // ✅ Seed Alice if not exists
            users.findByUsername("alice").ifPresentOrElse(
                u -> System.out.println("User 'alice' already exists — skipping seeding."),
                () -> {
                    AppUser alice = users.save(AppUser.builder()
                            .username("alice")
                            .password(passwordEncoder.encode("alice123"))
                            .email("alice@cydea.tech")
                            .role("USER")
                            .isAdmin(false)
                            .build());

                    accounts.save(Account.builder()
                            .ownerUserId(alice.getId())
                            .iban("PK00-ALICE")
                            .balance(1000.0)
                            .build());

                    System.out.println("✅ Seeded user: alice");
                }
            );

            // ✅ Seed Bob if not exists
            users.findByUsername("bob").ifPresentOrElse(
                u -> System.out.println("User 'bob' already exists — skipping seeding."),
                () -> {
                    AppUser bob = users.save(AppUser.builder()
                            .username("bob")
                            .password(passwordEncoder.encode("bob123"))
                            .email("bob@cydea.tech")
                            .role("ADMIN")
                            .isAdmin(true)
                            .build());

                    accounts.save(Account.builder()
                            .ownerUserId(bob.getId())
                            .iban("PK00-BOB")
                            .balance(5000.0)
                            .build());

                    System.out.println("✅ Seeded user: bob");
                }
            );

            System.out.println("✅ Data seeding check completed.");
        };
    }
}
