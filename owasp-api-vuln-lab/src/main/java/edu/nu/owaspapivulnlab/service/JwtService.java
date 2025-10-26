package edu.nu.owaspapivulnlab.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Date;
import java.util.Map;

@Service
public class JwtService {

    private static final int MIN_KEY_BYTES = 32; // HS256 needs at least 256 bits

    private final SecretKey signingKey;
    private final Duration ttl;
    private final String issuer;
    private final String audience;

    public JwtService(@Value("${app.jwt.secret}") String secret,
                      @Value("${app.jwt.ttl-seconds:900}") long ttlSeconds,
                      @Value("${app.jwt.issuer}") String issuer,
                      @Value("${app.jwt.audience}") String audience) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException("app.jwt.secret must be supplied (preferably via environment variable)");
        }
        this.signingKey = buildSigningKey(secret);
        if (ttlSeconds <= 0 || ttlSeconds > Duration.ofHours(24).getSeconds()) {
            throw new IllegalStateException("app.jwt.ttl-seconds must be between 1 second and 24 hours");
        }
        this.ttl = Duration.ofSeconds(ttlSeconds);
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalStateException("app.jwt.issuer must be provided");
        }
        if (audience == null || audience.isBlank()) {
            throw new IllegalStateException("app.jwt.audience must be provided");
        }
        this.issuer = issuer;
        this.audience = audience;
    }

    private SecretKey buildSigningKey(String rawSecret) {
        byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(rawSecret);
        } catch (IllegalArgumentException ignored) {
            keyBytes = rawSecret.getBytes(StandardCharsets.UTF_8);
        }
        if (keyBytes.length < MIN_KEY_BYTES) {
            throw new IllegalStateException("JWT secret must be at least 256 bits");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String issue(String subject, Map<String, Object> claims) {
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("JWT subject is required");
        }
        long now = System.currentTimeMillis();
        long expiry = now + ttl.toMillis();

        var builder = Jwts.builder()
                .setSubject(subject)
                .setIssuer(issuer)
                .setAudience(audience)
                .setIssuedAt(new Date(now))
                .setExpiration(new Date(expiry));

        if (claims != null && !claims.isEmpty()) {
            builder.addClaims(claims);
        }

        return builder.signWith(signingKey, SignatureAlgorithm.HS256).compact();
    }

    public Claims validate(String token) {
        return Jwts.parserBuilder()
                .requireIssuer(issuer)
                .requireAudience(audience)
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}

