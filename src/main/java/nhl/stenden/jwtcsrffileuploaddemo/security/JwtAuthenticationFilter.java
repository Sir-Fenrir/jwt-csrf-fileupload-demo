package nhl.stenden.jwtcsrffileuploaddemo.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * A normal Spring MVC app logs you in once, keeps an {@code HttpSession} on the server,
 * and reads that session back on every later request. We're not doing that here, there's
 * no session at all. Instead, this filter runs in front of every single request and asks
 * one question: "does this request carry a cookie with a JWT in it, and if so, is it
 * genuine?" If yes, it tells the rest of Spring Security "this request belongs to this
 * user", exactly as if a login had just happened, and the request carries on as normal.
 * <p>
 * It's registered to run before Spring Security's own username/password filter, since this
 * demo never uses that one, every request authenticates through a token, not a login form.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter
{

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService)
    {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException
    {
        String token = this.extractToken(request);

        if (token != null && SecurityContextHolder.getContext().getAuthentication() == null)
        {
            try
            {
                String username = this.jwtService.extractUsername(token);
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

                if (this.jwtService.isTokenValid(token, userDetails))
                {
                    var authenticationToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                }
            }
            catch (InvalidJwtException | UsernameNotFoundException ex)
            {
                // Bad or stale token: we don't fail the request here, we just leave it
                // unauthenticated. Whatever endpoint it's headed for will reject it with a
                // 401 if it actually required a logged-in user.
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Cookies arrive as a flat array with no convenient lookup method, so we have to check
     * it ourselves looking for the one with the name our cookie uses.
     */
    private String extractToken(HttpServletRequest request)
    {
        Cookie[] cookies = request.getCookies();

        if (cookies == null)
        {
            return null;
        }

        for (Cookie cookie : cookies)
        {
            if (JwtService.ACCESS_TOKEN_COOKIE.equals(cookie.getName()))
            {
                return cookie.getValue();
            }
        }

        return null;
    }
}
