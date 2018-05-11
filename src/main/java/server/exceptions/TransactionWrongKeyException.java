package server.exceptions;

@SuppressWarnings("serial")
public class TransactionWrongKeyException extends Exception{

	public TransactionWrongKeyException(String message) {
		super(message);
	}

}
