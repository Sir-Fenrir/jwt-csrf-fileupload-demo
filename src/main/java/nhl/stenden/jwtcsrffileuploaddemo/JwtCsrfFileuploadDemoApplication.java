package nhl.stenden.jwtcsrffileuploaddemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point of the application. Spring Boot scans this package (and everything underneath it)
 * for the beans it needs to wire together: the security filter chain, the controllers,
 * the services. You don't need to touch this class for anything in this project.
 */
@SpringBootApplication
public class JwtCsrfFileuploadDemoApplication
{

    static void main(String[] args)
    {
        SpringApplication.run(JwtCsrfFileuploadDemoApplication.class, args);
    }
}
