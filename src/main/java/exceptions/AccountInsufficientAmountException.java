package exceptions;

@SuppressWarnings("serial")
public class AccountInsufficientAmountException extends Exception {
    public AccountInsufficientAmountException() {
        super("There are not enough coins in your account");
    }
}
