package server.exceptions;

@SuppressWarnings("serial")
public class SameSourceAndDestAccountException extends Exception{

	public SameSourceAndDestAccountException() {
		super("Source and destination are the same");
	}

}
