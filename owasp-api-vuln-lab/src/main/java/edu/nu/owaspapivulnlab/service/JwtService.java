package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map; // <-- Make sure this is imported

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String secret;

    private SecretKey getSigningKey() {
        // This creates a proper SecretKey from the secret string in application.properties
        byte[] keyBytes = this.secret.getBytes(StandardCharsets.UTF_8);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * --- FIX: Renamed this method to 'issue' to match what AuthController is calling ---
     *
     * @param subject The subject of the token (usually the username)
     * @param claims A map of claims to include (e.g., "role": "USER")
     * @return A signed JWT string
     */
    public String issue(String subject, Map<String, Object> claims) {
        long now = System.currentTimeMillis();
        // VULNERABILITY: Token expires in 1 day - very long!
        long expiry = now + (24 * 60 * 60 * 1000); 

        return Jwts.builder()
                .setSubject(subject)
                .addClaims(claims) // Add all claims from the map
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(expiry))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}

