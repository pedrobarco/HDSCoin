package domain;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

@DatabaseTable(tableName = "transactions")
public class Transaction {
    @DatabaseField(generatedId=true)
    public int id;
    @DatabaseField(foreign = true)
    private Account from;
    @DatabaseField(foreign = true)
    public Account to;
    @DatabaseField
    private int amount;
    @DatabaseField
    private boolean pending;

    public Transaction() {

    }

    public Transaction(Account from, Account to, int amount) {
        this.from = from;
        this.to = to;
        this.amount = amount;
        this.pending = true;
    }

    public Transaction(Account from, Account to, int amount, boolean pending) {
        this.from = from;
        this.to = to;
        this.amount = amount;
        this.pending = pending;
    }

    public Account getFrom() {
        return from;
    }

    public void setFrom(Account from) {
        this.from = from;
    }

    public Account getTo() {
        return to;
    }

    public void setTo(Account to) {
        this.to = to;
    }

    public int getAmount() {
        return amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
    }

    public void setId(int id) {
        this.id = id;
    }

    public int getId() {
        return id;
    }

    public void setPending(boolean pending) {
        this.pending = pending;
    }

    @Override
    public String toString() {
        return "From: " + from.getKey() + "\nTo: " + to.getKey() + "\nAmount: " + amount;
    }
}
