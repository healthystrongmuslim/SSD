package edu.nu.owaspapivulnlab.web.dto;

import edu.nu.owaspapivulnlab.model.AppUser;
import java.util.Objects;

/**
 * A Data Transfer Object (DTO) used to securely send user data to the client.
 * This class is the Java 8 / 11 compatible version of a 'record'.
 * It excludes sensitive fields like password, role, and isAdmin.
 */
public final class UserResponseDTO {
    
    // 1. Private fields
    private final Long id;
    private final String username;
    private final String email;

    // 2. Constructor to initialize the fields
    public UserResponseDTO(Long id, String username, String email) {
        this.id = id;
        this.username = username;
        this.email = email;
    }

    // 3. Static factory method (this is what your Controller uses)
    public static UserResponseDTO fromEntity(AppUser user) {
        return new UserResponseDTO(
            user.getId(),
            user.getUsername(),
            user.getEmail()
        );
    }

    // 4. Public "getter" methods so Jackson (the JSON converter) can read the fields
    public Long getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getEmail() {
        return email;
    }

    // 5. (Optional but good practice) equals() and hashCode()
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        UserResponseDTO that = (UserResponseDTO) obj;
        return Objects.equals(id, that.id) &&
               Objects.equals(username, that.username) &&
               Objects.equals(email, that.email);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, username, email);
    }
}
