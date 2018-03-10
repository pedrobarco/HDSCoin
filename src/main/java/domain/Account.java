package domain;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

public class Account {
    private int amount;
    private int key;
    private List<Transaction> transactions;
    private List<Transaction> pendingTransactions;

    public Account(int key) {
        setKey(key);
        setAmount(100);
        transactions = new LinkedList<>();
        pendingTransactions = new LinkedList<>();
    }
    public int getAmount() {
        return amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
    }

    public int getKey() {
        return key;
    }

    public void setKey(int key) {
        this.key = key;
    }

    public void addTransaction(Transaction transaction) {
        pendingTransactions.add(transaction);
    }

    public void completeTransaction(Transaction transaction) {
        if (transaction.getTo() == this) {
           this.setAmount(this.getAmount() + transaction.getAmount());
        } else {
            this.setAmount(this.getAmount() - transaction.getAmount());
        }
        pendingTransactions.remove(transaction);
        transactions.add(transaction);
    }

    public List<Transaction> getTransactions() {
        return transactions;
    }

    public List<Transaction> getPendingTransactions() {
        return pendingTransactions;
    }

    public Transaction getPendingIncomingTransactionById(int id){
        return pendingTransactions.stream().filter(t -> t.getTo() == this && t.getId() == id).findFirst().orElse(null);
    }

    public List<Transaction> getPendingIncomingTransactions(){
        return pendingTransactions.stream().filter(t -> t.getTo() == this).collect(Collectors.toList());
    }
}
