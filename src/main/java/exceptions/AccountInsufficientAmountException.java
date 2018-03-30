package exceptions;

@SuppressWarnings("serial")
public class AccountInsufficientAmountException extends Exception {
    public AccountInsufficientAmountException(String message) {
        super(message);
    }
}
