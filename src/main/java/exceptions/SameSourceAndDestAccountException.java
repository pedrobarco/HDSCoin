package exceptions;

@SuppressWarnings("serial")
public class SameSourceAndDestAccountException extends Exception{

	public SameSourceAndDestAccountException(String message) {
		super(message);
	}

}
