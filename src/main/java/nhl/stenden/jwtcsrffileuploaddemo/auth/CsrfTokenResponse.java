package nhl.stenden.jwtcsrffileuploaddemo.auth;

/**
 * A copy of the CSRF token for whoever's curious enough to inspect the response body. The
 * frontend in this demo doesn't actually read this, it just reads the {@code XSRF-TOKEN}
 * cookie that gets set as a side effect of this same request, see {@code app.js}.
 */
public record CsrfTokenResponse(String token, String headerName)
{
}
