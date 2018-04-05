package domain;

import java.io.Serializable;
import java.util.List;

public class AccountState implements Serializable{

    private String keyHash;
    private int amount;
    private List<Transaction> pendingTransactions;

    public AccountState(String keyHash, int amount, List<Transaction> pendingTransactions) {
        this.keyHash = keyHash;
        this.amount = amount;
        this.pendingTransactions = pendingTransactions;
    }

    public String getKeyHash() {
        return keyHash;
    }

    public void setKeyhash(String key) {
        this.keyHash = keyHash;
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
