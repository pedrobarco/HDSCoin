package server.exceptions;

@SuppressWarnings("serial")
public class TransactionAlreadyReceivedException extends Exception {
    public TransactionAlreadyReceivedException(String message) {
        super(message);
    }
}
