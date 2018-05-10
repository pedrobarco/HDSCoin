package exceptions;

public class WritebackMismatchedTransactionException extends Exception {
    public WritebackMismatchedTransactionException(String tid1, String tid2) {
        super("Can't add writeback ledger due to mismatched transactions:\nCurrent: "+tid1+"\nTo add: "+tid2);
    }
}
