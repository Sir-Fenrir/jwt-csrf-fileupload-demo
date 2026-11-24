package nhl.stenden.jwtcsrffileuploaddemo.web;

/**
 * The one JSON shape every error response in this app uses: {@code {"error": "<message>"}}.
 * {@code ApiExceptionHandler} builds these for exceptions thrown inside a controller;
 * {@code SecurityConfig} builds them by hand for failures (like a bad CSRF token) that
 * never make it as far as a controller. One shape, so the frontend only has to know how
 * to read an error once, see {@code app.js}.
 */
public record ErrorDTO(String error)
{
}
