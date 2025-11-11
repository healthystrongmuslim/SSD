package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.model.Account;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.repo.AccountRepository;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;
import org.springframework.web.bind.annotation.*;

// --- Imports for Ownership Check ---
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;
// ---

import java.util.List;

@RestController
@RequestMapping("/api/accounts")
public class AccountController {

    private final AccountRepository accountRepository;
    private final AppUserRepository userRepository;

    public AccountController(AccountRepository accountRepository, AppUserRepository userRepository) {
        this.accountRepository = accountRepository;
        this.userRepository = userRepository;
    }

    // --- Helper method to get the currently logged-in user ---
    private AppUser getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Authenticated user not found"));
    }
    // ---

    // --- FIX: This endpoint now checks for ownership ---
    // (Assuming you have an endpoint like this. Adapt to your code)
    @GetMapping("/user/{userId}")
    public List<Account> getAccountsForUser(@PathVariable Long userId) {
        AppUser authenticatedUser = getAuthenticatedUser();

        // 1. Allow if they are an ADMIN
        // 2. Allow if they are requesting their own user ID
        if (!authenticatedUser.getRole().equals("ADMIN") && !authenticatedUser.getId().equals(userId)) {
            // If neither, deny access.
            throw new AccessDeniedException("You are not authorized to access this resource.");
        }

        return accountRepository.findByOwnerUserId(userId);
    }

    // (You might also have a GET /api/accounts endpoint to just get your *own* accounts)
    @GetMapping
    public List<Account> getMyAccounts() {
        AppUser authenticatedUser = getAuthenticatedUser();
        return accountRepository.findByOwnerUserId(authenticatedUser.getId());
    }
}
