package exceptions;

@SuppressWarnings("serial")
public class RepeatedTransactionException extends Exception{
	public RepeatedTransactionException() {
		super("Duplicate transaction");
	}
}
