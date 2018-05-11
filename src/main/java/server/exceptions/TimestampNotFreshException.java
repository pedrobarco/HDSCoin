package server.exceptions;

@SuppressWarnings("serial")
public class TimestampNotFreshException extends Exception{

	public TimestampNotFreshException(String message) {
		super(message);
	}

}
