package server.exceptions;

@SuppressWarnings("serial")
public class InvalidAmountException extends Exception{
	public InvalidAmountException() {
		super("Amount must be a positive integer");
	}
}
