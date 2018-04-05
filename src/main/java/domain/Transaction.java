package domain;

import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

import java.io.Serializable;

@SuppressWarnings("serial")
@DatabaseTable(tableName = "transactions")
public class Transaction implements Serializable{

	@DatabaseField(generatedId=true)
    private int id;
    @DatabaseField(foreign = true, foreignAutoRefresh = true)
    private Account from;
    @DatabaseField(foreign = true, foreignAutoRefresh = true)
    private Account to;
    @DatabaseField
    private int amount;
    @DatabaseField
    private boolean pending;

    public Transaction() {

    }

    // TODO IMPORTANT!!! STORE SIGNATURE
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

    public boolean isPending(){
        return this.pending;
    }

    public void setPending(boolean pending) {
        this.pending = pending;
    }

    @Override
    public String toString() {
        return "From: " + from.getKey() + "\nTo: " + to.getKey() + "\nAmount: " + amount;
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        if (!Transaction.class.isAssignableFrom(obj.getClass())) {
            return false;
        }
        final Transaction other = (Transaction) obj;
        if (this.id != other.id) {
            return false;
        }
        if (this.from.getKeyHash() != other.from.getKeyHash()){
            return false;
        }
        if (this.to.getKeyHash() != other.to.getKeyHash()){
            return false;
        }
        if (this.amount != other.amount){
            return false;
        }
        if (this.pending != other.pending){
            return false;
        }
        return true;
    }

}
