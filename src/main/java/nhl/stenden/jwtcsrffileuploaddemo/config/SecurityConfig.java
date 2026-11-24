package nhl.stenden.jwtcsrffileuploaddemo.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nhl.stenden.jwtcsrffileuploaddemo.security.JwtAuthenticationFilter;
import nhl.stenden.jwtcsrffileuploaddemo.web.ErrorDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

/**
 * Everything security-related in this demo comes together here. Two separate concerns,
 * both worth understanding on their own before you read the bean methods below.
 * <p>
 * <strong>Authentication</strong> (who are you?) happens via the JWT in the
 * {@code ACCESS_TOKEN} cookie, checked by {@link JwtAuthenticationFilter}. There is no
 * {@code HttpSession} anywhere in this app, {@link SessionCreationPolicy#STATELESS} below
 * means Spring won't even create one.
 * <p>
 * <strong>CSRF protection</strong> (is this request really coming from our own page?) is
 * the more difficult one. Picture a festival wristband: the gate scans it automatically, every
 * time, without asking questions. That's exactly how a browser treats cookies, it attaches
 * them to every request to that domain, including one triggered by a dodgy site you happen
 * to have open in another tab that quietly submits a hidden form to this API. The wristband alone
 * proves nothing about who's actually asking. So for anything that changes state (in
 * practice, a POST, PUT or DELETE), we additionally require a value that only JavaScript running on our own
 * page could have read: a token from a second, non-httpOnly cookie, echoed back in a request
 * header. A page on evil.example can trigger your browser into sending the wristband along (the cookie),
 * but it can never read that second cookie to produce the matching header, browsers simply
 * don't allow that across origins. This is Spring Security's "double submit cookie" pattern,
 * setup below with {@link CookieCsrfTokenRepository}.
 */
@Configuration
public class SecurityConfig
{

    private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    /**
     * Two accounts, hardcoded, so the demo doesn't need a database just to show JWTs, CSRF
     * and file upload in action. Swap this out for a database-backed
     * {@link UserDetailsService} the moment you need real users.
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder)
    {
        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder.encode("admin123"))
                .roles("ADMIN", "USER")
                .build();
        UserDetails user = User.withUsername("user")
                .password(passwordEncoder.encode("user123"))
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }

    /**
     * The thing that actually checks a submitted username and password against
     * {@code userDetailsService}, using {@code passwordEncoder} to compare the submitted
     * password against the stored BCrypt hash. {@code AuthController} calls this directly
     * during login.
     */
    @Bean
    public AuthenticationManager authenticationManager(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder)
    {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);

        return new ProviderManager(provider);
    }

    /**
     * This method wires everything all together!
     * It sets up CSRF protection, the no-session setup, which URL's are protected and which aren't,
     * adding the JWT authentication filter and how to deal with Exceptions.
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter, ObjectMapper objectMapper)
            throws Exception
    {
        http
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        // The page itself, and the CSS/JS it loads, must stay reachable
                        // before anyone has logged in, otherwise nobody could ever see the
                        // login form in the first place.
                        .requestMatchers("/", "/index.html", "/css/**", "/js/**", "/favicon.ico").permitAll()
                        // Fetching a CSRF token is how the frontend bootstraps itself, so
                        // it has to stay open to logged-out visitors too.
                        .requestMatchers(HttpMethod.GET, "/api/auth/csrf").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/auth/login").permitAll()
                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        // Fires when a request has no valid authentication at all, for
                        // example a missing or expired ACCESS_TOKEN cookie on /api/files.
                        .authenticationEntryPoint(
                                (request, response, authException) ->
                                        writeError(response, objectMapper, 401, describeFailure(request, authException, "Authentication is required"))
                        )
                        // CsrfFilter calls this handler directly the moment it rejects a
                        // request, before authentication is even checked, so this is the one
                        // that actually sees CSRF failures, regardless of whether the request
                        // was logged in or not. It also fires for an authenticated user who's
                        // missing a permission, which nothing in this demo currently checks
                        // for, if you add role-restricted endpoints later, their rejections
                        // land here too.
                        .accessDeniedHandler(
                                (request, response, accessDeniedException) ->
                                        writeError(response, objectMapper, 403, describeFailure(request, accessDeniedException, "Access is denied"))
                        )
                )
                // We built our own JSON login flow in AuthController, so switch off the two
                // login mechanisms Spring Security would otherwise offer out of the box.
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /**
     * Logs exactly what went wrong and returns the message to send back to the client.
     * The CSRF cases are logged at WARN, since they usually mean a real bug (a frontend
     * that forgot the header, or a stale page that never fetched a token), while any other
     * rejection is logged at DEBUG, it's often just a page load happening before login.
     */
    private static String describeFailure(HttpServletRequest request, Exception exception, String fallbackMessage)
    {
        if (exception instanceof MissingCsrfTokenException)
        {
            log.warn("CSRF token missing on {} {}: no X-XSRF-TOKEN header was sent alongside the XSRF-TOKEN cookie",
                    request.getMethod(), request.getRequestURI());

            return "CSRF token is missing";
        }

        if (exception instanceof InvalidCsrfTokenException)
        {
            log.warn("CSRF token invalid on {} {}: the X-XSRF-TOKEN header did not match the XSRF-TOKEN cookie",
                    request.getMethod(), request.getRequestURI());

            return "CSRF token is invalid";
        }

        log.debug("Rejected {} {}: {}", request.getMethod(), request.getRequestURI(), fallbackMessage);

        return fallbackMessage;
    }

    private static void writeError(HttpServletResponse response, ObjectMapper objectMapper, int status, String message)
            throws IOException
    {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        objectMapper.writeValue(response.getWriter(), new ErrorDTO(message));
    }
}
