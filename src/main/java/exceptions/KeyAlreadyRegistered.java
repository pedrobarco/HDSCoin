package exceptions;

@SuppressWarnings("serial")
public class KeyAlreadyRegistered extends Exception {
	public KeyAlreadyRegistered(String message) {
		super(message);
	}
}
