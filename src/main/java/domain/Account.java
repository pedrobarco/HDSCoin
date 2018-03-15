package domain;

import com.j256.ormlite.dao.ForeignCollection;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.field.ForeignCollectionField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "accounts")
public class Account {
    @DatabaseField(id=true)
    private int key;
    @DatabaseField
    private int amount;
    @ForeignCollectionField
    private ForeignCollection<Transaction> transactions;

    public Account() {

    }

    public Account(int key) {
        this.key = key;
        this.amount = 100;
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

    public void completeTransaction(Transaction transaction) {
        if (transaction.getTo() == this) {
           this.setAmount(this.getAmount() + transaction.getAmount());
        } else {
            this.setAmount(this.getAmount() - transaction.getAmount());
        }
        transaction.setPending(false);
    }

    public ForeignCollection<Transaction> getTransactions() {
        return transactions;
    }

    @Override
    public String toString() {
        return "Key: " + key + "\nBalance: " + amount;
    }
}
