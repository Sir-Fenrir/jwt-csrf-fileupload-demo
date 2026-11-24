package nhl.stenden.jwtcsrffileuploaddemo.auth;

/**
 * The JSON body the frontend sends to {@code POST /api/auth/login}: just the two fields
 * from the login form, nothing fancier.
 */
public record LoginRequest(String username, String password)
{
}
