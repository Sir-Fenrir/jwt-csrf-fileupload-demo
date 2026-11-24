package nhl.stenden.jwtcsrffileuploaddemo.files;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;

/**
 * Everything to do with uploaded files living on disk: writing them, listing them, reading
 * one back.
 */
@Service
public class FileStorageService
{

    private final Path uploadDir;

    public FileStorageService(@Value("${app.upload.dir}") String uploadDir)
    {
        this.uploadDir = Path.of(uploadDir).toAbsolutePath().normalize();

        try
        {
            Files.createDirectories(this.uploadDir);
        }
        catch (IOException ex)
        {
            throw new UncheckedIOException("Could not create upload directory: " + this.uploadDir, ex);
        }
    }

    public UploadedFileResponse store(MultipartFile file)
    {
        String name = file.getOriginalFilename();

        try
        {
            Files.copy(file.getInputStream(), this.uploadDir.resolve(name), StandardCopyOption.REPLACE_EXISTING);
        }
        catch (IOException ex)
        {
            throw new UncheckedIOException("Failed to store file: " + name, ex);
        }

        return new UploadedFileResponse(name, name, file.getSize());
    }

    public List<UploadedFileResponse> listFiles()
    {
        try (Stream<Path> paths = Files.list(this.uploadDir))
        {
            return paths
                    .filter(Files::isRegularFile)
                    .sorted(Comparator.comparing(path -> path.getFileName().toString()))
                    .map(this::toResponse)
                    .toList();
        }
        catch (IOException ex)
        {
            throw new UncheckedIOException("Failed to list uploaded files", ex);
        }
    }

    public Resource loadAsResource(String name)
    {
        Path path = this.uploadDir.resolve(name);

        if (!Files.isRegularFile(path))
        {
            throw new IllegalArgumentException("File not found: " + name);
        }

        try
        {
            return new UrlResource(path.toUri());
        }
        catch (MalformedURLException ex)
        {
            throw new IllegalArgumentException("File not found: " + name);
        }
    }

    private UploadedFileResponse toResponse(Path path)
    {
        String name = path.getFileName().toString();
        long size;

        try
        {
            size = Files.size(path);
        }
        catch (IOException ex)
        {
            throw new UncheckedIOException(ex);
        }

        return new UploadedFileResponse(name, name, size);
    }
}
