package nhl.stenden.jwtcsrffileuploaddemo.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

/**
 * Think of a JWT (JSON Web Token) as a little signed note the server hands out: "I checked
 * this person's password, their name is Kaladin, and this note is valid until 15:42." The
 * note itself is just text, split into three base64 parts separated by dots (header, the
 * claims, and a signature). Anyone can read it, but only the server, holding the secret key,
 * could have produced that signature. So on every later request, the server doesn't need to
 * remember anything about the user, it just re-checks the signature on the note it already
 * handed out. That's what "stateless" authentication means.
 * <p>
 * This class is the only place that knows how to write and verify those notes. It also
 * builds the cookie the note travels in. We deliberately use an <em>httpOnly</em> cookie
 * (JavaScript on the page can't read it) instead of handing the token back in the response
 * body for the frontend to stash in localStorage. That choice is what makes the CSRF
 * protection in {@link nhl.stenden.jwtcsrffileuploaddemo.config.SecurityConfig} useful:
 * because the browser attaches this cookie to every request automatically, a request forged
 * from a completely different website would carry it too, unless something stops it.
 */
@Service
public class JwtService
{

    public static final String ACCESS_TOKEN_COOKIE = "ACCESS_TOKEN";

    private final SecretKey key;
    private final long expirationMinutes;

    public JwtService(
            @Value("${app.jwt.secret}") String secret,
            @Value("${app.jwt.expiration-minutes:60}") long expirationMinutes)
    {
        // HMAC-SHA256 needs a key of exactly 256 bits. Hashing the configured secret gets
        // us there no matter how long the phrase in application.properties is, a one-word
        // secret and a 40-character one both end up as a valid key this way.
        this.key = Keys.hmacShaKeyFor(sha256(secret));
        this.expirationMinutes = expirationMinutes;
    }

    private static byte[] sha256(String text)
    {
        try
        {
            return MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new IllegalStateException("SHA-256 is not available", ex);
        }
    }

    /**
     * Writes a new signed token for the given user: who they are, which roles they have,
     * and when the token expires. Nothing is stored anywhere, this one string is the
     * entire "session".
     */
    public String generateToken(UserDetails userDetails)
    {
        Instant now = Instant.now();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return Jwts.builder()
                .subject(userDetails.getUsername())
                .claim("roles", roles)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plus(this.expirationMinutes, ChronoUnit.MINUTES)))
                .signWith(this.key)
                .compact();
    }

    /**
     * Reads the username back out of a token, after checking the signature is genuine.
     * Throws {@link InvalidJwtException} for anything suspicious: an expired token, a
     * tampered one, or just garbage that isn't a JWT at all.
     */
    public String extractUsername(String token)
    {
        return this.parseClaims(token).getSubject();
    }

    /**
     * A token is only valid if it belongs to the user we think it does and hasn't expired yet.
     */
    public boolean isTokenValid(String token, UserDetails userDetails)
    {
        Claims claims = this.parseClaims(token);

        return claims.getSubject().equals(userDetails.getUsername())
                && claims.getExpiration().after(new Date());
    }

    private Claims parseClaims(String token)
    {
        try
        {
            return Jwts.parser()
                    .verifyWith(this.key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        }
        catch (JwtException | IllegalArgumentException ex)
        {
            throw new InvalidJwtException("Invalid or expired token", ex);
        }
    }

    /**
     * Builds the Set-Cookie header value that carries a freshly issued token.
     */
    public ResponseCookie buildAccessTokenCookie(String token)
    {
        return ResponseCookie.from(ACCESS_TOKEN_COOKIE, token)
                .httpOnly(true)
                .secure(false) // We're not using HTTPS, so we're skipping this for now
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofMinutes(this.expirationMinutes))
                .build();
    }

    /**
     * Same cookie, but with its value cleared and its max age set to zero, which tells the
     * browser "throw this one away". This is for logging out.
     */
    public ResponseCookie buildExpiredAccessTokenCookie()
    {
        return ResponseCookie.from(ACCESS_TOKEN_COOKIE, "")
                .httpOnly(true)
                .secure(false) // We're not using HTTPS, so we're skipping this for now
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();
    }
}
