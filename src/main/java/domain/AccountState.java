package domain;

import java.util.List;

public class AccountState {

    private String key;
    private int amount;
    private List<Transaction> pendingTransactions;

    public AccountState(String key, int amount, List<Transaction> pendingTransactions) {
        this.key = key;
        this.amount = amount;
        this.pendingTransactions = pendingTransactions;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
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
