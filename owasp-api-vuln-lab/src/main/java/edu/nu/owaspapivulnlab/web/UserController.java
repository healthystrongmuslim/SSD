package edu.nu.owaspapivulnlab.web;

import edu.nu.owaspapivulnlab.web.dto.UserResponseDTO; // <-- 1. Import the new DTO
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import edu.nu.owaspapivulnlab.model.AppUser;
import edu.nu.owaspapivulnlab.web.dto.UserCreateDTO;
import edu.nu.owaspapivulnlab.repo.AppUserRepository;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;

import java.util.HashMap;
import java.util.List; // <-- 2. Keep this import
import java.util.Map;
import java.util.stream.Collectors; // <-- 3. Add this import for streaming

import org.springframework.security.crypto.password.PasswordEncoder;


@RestController
@RequestMapping("/api/users")
public class UserController {
    private final AppUserRepository users;
    private final PasswordEncoder passwordEncoder; 

    public UserController(AppUserRepository users, PasswordEncoder passwordEncoder) {
        this.users = users;
        this.passwordEncoder = passwordEncoder; 
    }

    private AppUser getAuthenticatedUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String username = authentication.getName();
        return users.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("Authenticated user not found"));
    }

    // --- FIX: Return type changed to UserResponseDTO ---
    @GetMapping("/{id}")
    public UserResponseDTO get(@PathVariable("id") Long id) {
        AppUser authenticatedUser = getAuthenticatedUser();

        if (!authenticatedUser.getRole().equals("ADMIN") && !authenticatedUser.getId().equals(id)) {
            throw new AccessDeniedException("You are not authorized to access this resource.");
        }

        AppUser user = users.findById(id).orElseThrow(() -> new RuntimeException("User not found"));
        
        // --- 4. Convert the entity to a safe DTO before returning ---
        return UserResponseDTO.fromEntity(user);
    }
    
    // --- FIX: Return type changed to UserResponseDTO ---
    @PostMapping
    public ResponseEntity<UserResponseDTO> create(@Valid @RequestBody UserCreateDTO body) {
        // Map only allowed fields from DTO -> entity to prevent mass assignment of role/isAdmin
        AppUser toSave = new AppUser();
        toSave.setUsername(body.getUsername());
        toSave.setPassword(passwordEncoder.encode(body.getPassword()));
        toSave.setEmail(body.getEmail());
        // Enforce default non-privileged role
        toSave.setRole("USER");
        toSave.setAdmin(false);

        AppUser savedUser = users.save(toSave);

        // Return 201 Created with safe DTO (no password/role/isAdmin fields)
        UserResponseDTO dto = UserResponseDTO.fromEntity(savedUser);
        return ResponseEntity.status(201).body(dto);
    }

    // --- FIX: Return type changed to List<UserResponseDTO> ---
    @GetMapping("/search")
    public List<UserResponseDTO> search(@RequestParam String q) {
        List<AppUser> foundUsers = users.search(q);
        
        // --- 6. Convert the list of entities to a list of DTOs ---
        return foundUsers.stream()
                         .map(UserResponseDTO::fromEntity)
                         .collect(Collectors.toList());
    }

    // --- FIX: Return type changed to List<UserResponseDTO> ---
    @GetMapping
    public List<UserResponseDTO> list() {
        List<AppUser> allUsers = users.findAll();
        
        // --- 7. Convert the list of entities to a list of DTOs ---
        return allUsers.stream()
                       .map(UserResponseDTO::fromEntity)
                       .collect(Collectors.toList());
    }

    // (This endpoint is fine, no changes needed as it doesn't return user data)
    @DeleteMapping("/{id}")
    public ResponseEntity<?> delete(@PathVariable("id") Long id) {
        users.deleteById(id);
        Map<String, String> response = new HashMap<>();
        response.put("status", "deleted");
        return ResponseEntity.ok(response);
    }
}