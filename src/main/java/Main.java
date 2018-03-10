import exceptions.AccountInsufficientAmountException;
import exceptions.AccountNotFoundException;
import exceptions.TransactionNotFoundException;

public class Main {
    public static void main(String[] args) {
        HDSLib hdsLib = new HDSLib();
        hdsLib.register(1);
        hdsLib.register(2);
        try {
            hdsLib.sendAmount(1, 2, 50);
            System.out.println(hdsLib.audit(1));
            hdsLib.receiveAmount(1, 2, 0);
            System.out.println(hdsLib.audit(1));

        } catch (AccountNotFoundException e) {
            e.printStackTrace();
        } catch (AccountInsufficientAmountException e) {
            e.printStackTrace();
        } catch (TransactionNotFoundException e) {
            e.printStackTrace();
        }
    }
}