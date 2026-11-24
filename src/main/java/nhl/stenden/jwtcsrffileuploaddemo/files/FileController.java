package nhl.stenden.jwtcsrffileuploaddemo.files;

import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

/**
 * List, upload and download, the three things a file-sharing endpoint needs. Listing and
 * downloading are GETs, so they only need a valid {@code ACCESS_TOKEN} cookie. Uploading is
 * a POST, a state-changing request, so it additionally needs a matching {@code X-XSRF-TOKEN}
 * header, see {@code SecurityConfig} for why that's required.
 */
@RestController
@RequestMapping("/api/files")
public class FileController
{

    private final FileStorageService fileStorageService;

    public FileController(FileStorageService fileStorageService)
    {
        this.fileStorageService = fileStorageService;
    }

    @GetMapping
    public List<UploadedFileResponse> list()
    {
        return this.fileStorageService.listFiles();
    }

    @PostMapping
    public UploadedFileResponse upload(@RequestParam("file") MultipartFile file)
    {
        if (file.isEmpty())
        {
            throw new IllegalArgumentException("File must not be empty");
        }

        return this.fileStorageService.store(file);
    }

    @GetMapping("/{storedName}")
    public ResponseEntity<Resource> download(@PathVariable String storedName)
    {
        Resource resource = this.fileStorageService.loadAsResource(storedName);

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + storedName + "\"")
                .body(resource);
    }
}
