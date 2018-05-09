package client.domain;

import java.util.Map;

public class Account {
    private int balance;
    private Map<String, Transaction> pendingTransactions;

    public Account(int balance, Map<String, Transaction> pendingTransactions) {
        this.balance = balance;
        this.pendingTransactions = pendingTransactions;
    }

    public int getBalance() {
        return balance;
    }

    public Map<String, Transaction> getPendingTransactions() {
        return pendingTransactions;
    }

    @Override
    public boolean equals(Object obj){
        if (obj.getClass() != this.getClass()) {
            return false;
        }
        Account other = (Account) obj;
        if (other.getBalance() != this.balance) {
            return false;
        }
        return this.pendingTransactions.equals(other.getPendingTransactions());
    }

    @Override
    public int hashCode() {
        int hash = 3;
        hash = 53 * hash + (this.pendingTransactions != null ? this.pendingTransactions.hashCode() : 0);
        hash = 53 * hash + this.balance;
        return hash;
    }
}
