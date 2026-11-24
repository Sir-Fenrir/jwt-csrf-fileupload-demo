package nhl.stenden.jwtcsrffileuploaddemo.auth;

import java.util.List;

/**
 * What we tell the frontend about the logged-in user, so it can show "Welcome, Kaladin"
 * and decide which buttons to show. Deliberately doesn't include the token itself, the
 * token lives in an httpOnly cookie and JavaScript never gets to see it directly.
 */
public record UserResponse(String username, List<String> roles)
{
}
