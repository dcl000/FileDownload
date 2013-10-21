package fileDownload.config.exceptions;

public class FileDownloadException extends Exception{
	public FileDownloadException(String message) {
		super(message);
	}
	
	public FileDownloadException(String message, Throwable cause) {
        super(message, cause);
    }
	
	public FileDownloadException(Throwable cause) {
        super(cause);
    }
	
}
