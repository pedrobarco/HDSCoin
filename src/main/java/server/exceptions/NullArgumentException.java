package server.exceptions;

@SuppressWarnings("serial")
public class NullArgumentException extends Exception{

	public NullArgumentException(String message) {
		super(message);
	}

}
