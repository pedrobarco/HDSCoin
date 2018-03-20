package domain;

import com.j256.ormlite.dao.ForeignCollection;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.field.ForeignCollectionField;
import com.j256.ormlite.table.DatabaseTable;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@DatabaseTable(tableName = "accounts")
public class Account {
    @DatabaseField(id=true)
    private String keyHash;
    @DatabaseField
    private String key;
    @DatabaseField
    private int amount;
    @ForeignCollectionField
    private ForeignCollection<Transaction> transactions;

    public Account() {

    }

    public Account(String key) {
        this.key = key;
        this.amount = 100;
        try {
            MessageDigest digester = MessageDigest.getInstance("SHA-256");
            digester.update(key.getBytes());
            keyHash = Base64.getEncoder().encodeToString(digester.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    public int getAmount() {
        return amount;
    }

    public void setAmount(int amount) {
        this.amount = amount;
    }

    public void addAmount(int amount) {
        this.amount += amount;
    }

    public String getKeyHash() {
        return keyHash;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    /*public void completeTransaction(Transaction transaction) {
        if (transaction.getTo() == this) {
           this.setAmount(this.getAmount() + transaction.getAmount());
        } else {
            this.setAmount(this.getAmount() - transaction.getAmount());
        }
        transaction.setPending(false);
    }*/

    public ForeignCollection<Transaction> getTransactions() {
        return transactions;
    }

    @Override
    public String toString() {
        return "--- Account Object ---" +
                "\nKeyHash: " + keyHash +
                "\nBalance: " + amount +
                "\n-------";
    }
}
