package nhl.stenden.jwtcsrffileuploaddemo.auth;

import nhl.stenden.jwtcsrffileuploaddemo.security.JwtService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Everything a client needs to log in, log out, and find out who (if anyone) it currently
 * is. There's no {@code /register} here, the two accounts are hardcoded in
 * {@code SecurityConfig}, I'm leaving that for you.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController
{

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService)
    {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
    }

    /**
     * A plain GET the frontend calls once when the page loads. We don't actually care about
     * the response body, what matters is the side effect: reading {@code csrfToken} here
     * triggers Spring Security to generate a token and write it into the {@code XSRF-TOKEN}
     * cookie. Without this call, that cookie would never get set, since Spring only
     * generates the token lazily, the moment something asks for it.
     *
     * The CsrfToken parameter is automatically provided by Spring.
     */
    @GetMapping("/csrf")
    public CsrfTokenResponse csrf(CsrfToken csrfToken)
    {
        return new CsrfTokenResponse(csrfToken.getToken(), csrfToken.getHeaderName());
    }

    @PostMapping("/login")
    public ResponseEntity<UserResponse> login(@RequestBody LoginRequest request)
    {
        Authentication authentication = this.authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String token = this.jwtService.generateToken(userDetails);

        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, this.jwtService.buildAccessTokenCookie(token).toString())
                .body(this.toUserResponse(userDetails));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout()
    {
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, this.jwtService.buildExpiredAccessTokenCookie().toString())
                .build();
    }

    /**
     * We use this endpoint to retrieve information about the currently authenticated user.
     * In the lecture I showed putting the JWT in the Authorization header, but we can also use a (HTTP only) cookie.
     * This way, the JavaScript can't read the JWT, so it can't be stolen using injected JavaScript.
     * The downside is that because the frontend can't read the JWT, it can't use it to show stuff like 'role',
     * so we need to ask the API who we actually are.
     *
     * @param authentication The authentication object containing the user details, this is filled by Spring Security.
     * @return The user response containing the user's information.
     */
    @GetMapping("/me")
    public UserResponse me(Authentication authentication)
    {
        return this.toUserResponse((UserDetails) authentication.getPrincipal());
    }

    private UserResponse toUserResponse(UserDetails userDetails)
    {
        List<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return new UserResponse(userDetails.getUsername(), roles);
    }
}
