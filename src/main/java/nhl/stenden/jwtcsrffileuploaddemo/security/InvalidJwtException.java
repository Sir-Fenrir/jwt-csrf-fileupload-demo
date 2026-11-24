package nhl.stenden.jwtcsrffileuploaddemo.security;

/**
 * Thrown whenever {@link JwtService} is handed a token it can't trust: the signature
 * doesn't match, the token has expired, or it simply isn't a JWT at all. We wrap the
 * underlying jjwt exceptions in our own type so the rest of the application only has to
 * know about one failure case, not jjwt's whole exception hierarchy.
 */
public class InvalidJwtException extends RuntimeException
{

    public InvalidJwtException(String message, Throwable cause)
    {
        super(message, cause);
    }
}
