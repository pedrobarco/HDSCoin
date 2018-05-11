package server.exceptions;

@SuppressWarnings("serial")
public class InvalidSignatureException extends Exception{

	public InvalidSignatureException(String message) {
		super(message);
	}

}
