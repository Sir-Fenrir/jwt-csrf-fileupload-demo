package nhl.stenden.jwtcsrffileuploaddemo.web;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;

/**
 * Without this class, any exception thrown inside a controller method bubbles all the way
 * up and Spring MVC turns it into a generic 500 Internal Server Error, which tells a client
 * nothing useful. A {@code @RestControllerAdvice} catches exceptions by type across every
 * controller in the application, so we can translate the ones we expect (bad credentials,
 * an invalid file name, a file that's too big) into a proper HTTP status and an
 * {@link ErrorDTO} instead.
 */
@RestControllerAdvice
public class ApiExceptionHandler
{

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ErrorDTO> handleAuthenticationException(AuthenticationException ex)
    {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ErrorDTO("Invalid username or password"));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorDTO> handleIllegalArgument(IllegalArgumentException ex)
    {
        return ResponseEntity.badRequest().body(new ErrorDTO(ex.getMessage()));
    }

    @ExceptionHandler(MaxUploadSizeExceededException.class)
    public ResponseEntity<ErrorDTO> handleMaxUploadSize(MaxUploadSizeExceededException ex)
    {
        return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE)
                .body(new ErrorDTO("File is too large"));
    }
}
