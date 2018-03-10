import domain.Account;
import domain.AccountState;
import domain.Transaction;
import exceptions.AccountInsufficientAmountException;
import exceptions.AccountNotFoundException;
import exceptions.TransactionNotFoundException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class HDSLib {
    public Map<Integer, Account> accountList;
    public int transactionCounter;

    public HDSLib() {
        accountList = new HashMap<>();
        transactionCounter = 0;
    }

    public void register(int key){
        Account account = new Account(key);
        accountList.put(key, account);
    }

    public void sendAmount(int sourceKey, int destKey,  int amount) throws AccountNotFoundException, AccountInsufficientAmountException {
        Account sourceAccount = accountList.get(sourceKey);
        Account destAccount = accountList.get(destKey);
        if (sourceAccount == null) {
            throw new AccountNotFoundException("Source account not found!");
        } else if (destAccount == null) {
            throw new AccountNotFoundException("Destination account not found!");
        } else if (sourceAccount.getAmount() < amount) {
            throw new AccountInsufficientAmountException();
        }
        int id = transactionCounter++;
        Transaction transaction = new Transaction(sourceAccount, destAccount, amount, id);
        sourceAccount.addTransaction(transaction);
        destAccount.addTransaction(transaction);
    }

    public AccountState checkAccount(int key) throws AccountNotFoundException {
        Account account = accountList.get(key);
        if (account == null) {
            throw new AccountNotFoundException("Account not found!");
        }
        return new AccountState(account.getKey(), account.getAmount(), account.getPendingIncomingTransactions());
    }

    public void receiveAmount(int sourceKey, int destKey, int id) throws AccountNotFoundException, TransactionNotFoundException, AccountInsufficientAmountException {
        Account sourceAccount = accountList.get(sourceKey);
        Account destAccount = accountList.get(destKey);
        if (sourceAccount == null) {
            throw new AccountNotFoundException("Source account not found!");
        } else if (destAccount == null) {
            throw new AccountNotFoundException("Destination account not found!");
        }
        Transaction transaction = destAccount.getPendingIncomingTransactionById(id);
        if (transaction == null) {
            throw new TransactionNotFoundException();
        } else if (sourceAccount.getAmount() < transaction.getAmount()) {
            throw new AccountInsufficientAmountException();
        }
        sourceAccount.completeTransaction(transaction);
        destAccount.completeTransaction(transaction);
    }

    public List<Transaction> audit(int key) throws AccountNotFoundException {
        Account account = accountList.get(key);
        if (account == null) {
            throw new AccountNotFoundException("Account not found!");
        }
        return account.getTransactions();
    }
}
