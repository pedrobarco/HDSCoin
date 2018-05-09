package exceptions;

public class WrongPreviousTransactionException extends Exception {
    public WrongPreviousTransactionException(String given, String expected){
        super("Previous transaction hash doesn't match previous transaction. Got \"" +given + "\", expected \"" + expected + "\"");
    }
}
