package domain;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.j256.ormlite.dao.ForeignCollection;
import com.j256.ormlite.field.DataType;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.field.ForeignCollectionField;
import com.j256.ormlite.table.DatabaseTable;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

@SuppressWarnings("serial")
@DatabaseTable(tableName = "accounts")
public class Account implements Serializable{

	@DatabaseField(id=true)
    private String keyHash;
    @JsonIgnore
    @DatabaseField(dataType = DataType.SERIALIZABLE)
    private PublicKey key;
    @DatabaseField
    private int amount;
    @JsonIgnore
    @ForeignCollectionField(eager=true)
    private ForeignCollection<Transaction> transactions;

    public Account() {

    }

    public Account(PublicKey key) {
        this.key = key;
        this.amount = 100;
        try {
            MessageDigest digester = MessageDigest.getInstance("SHA-256"); //TODO mais tarde mudar o SHA 512
            digester.update(key.getEncoded());
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

    public PublicKey getKey() {
        return key;
    }

    public void setKey(PublicKey key) {
        this.key = key;
    }

    /* TODO: transaction list only keeps sent transactions
    public ForeignCollection<Transaction> getTransactions() {
        return transactions;
    }*/

    @Override
    public String toString() {
        return "--- Account Object ---" +
                "\nKeyHash: " + keyHash +
                "\nBalance: " + amount +
                "\n-------";
    }
}
