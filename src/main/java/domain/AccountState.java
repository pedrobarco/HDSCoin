package domain;

import java.util.List;

public class AccountState {

    public int key;
    public int amount;
    public List<Transaction> pendingTransactions;

    public AccountState(int key, int amount, List<Transaction> pendingTransactions) {
        setKey(key);
        setAmount(amount);
        setPendingTransactions(pendingTransactions);
    }

    public int getKey() {
        return key;
    }

    public void setKey(int key) {
        this.key = key;
    }

    public int getAmount() {
        return amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
    }

    public List<Transaction> getPendingTransactions() {
        return pendingTransactions;
    }

    public void setPendingTransactions(List<Transaction> pendingTransactions) {
        this.pendingTransactions = pendingTransactions;
    }
}
