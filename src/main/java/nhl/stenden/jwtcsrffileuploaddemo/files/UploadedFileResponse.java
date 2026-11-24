package nhl.stenden.jwtcsrffileuploaddemo.files;

/**
 * One row in the file list the frontend renders. {@code storedName} and
 * {@code originalName} are the same value right now, {@link FileStorageService} doesn't do
 * anything to the name a file is uploaded under, see its class comment.
 */
public record UploadedFileResponse(String storedName, String originalName, long sizeBytes)
{
}
