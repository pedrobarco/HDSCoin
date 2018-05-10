package domain;

import com.fasterxml.jackson.databind.JsonNode;
import com.j256.ormlite.field.DataType;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;
import org.jetbrains.annotations.NotNull;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;

@SuppressWarnings("serial")
@DatabaseTable(tableName = "transactions")
public class Transaction implements Serializable, Comparable{

	@DatabaseField(id=true)
    private String id;
	@DatabaseField
    private boolean last;
    @DatabaseField(foreign = true, foreignAutoRefresh = true)
    private Account from;
    @DatabaseField(foreign = true, foreignAutoRefresh = true)
    private Account to;
    @DatabaseField
    private int amount;

    @DatabaseField(foreign = true, foreignAutoRefresh = true)
    private Account owner;
    @DatabaseField
    private boolean receiving;
    @DatabaseField
    private int senderId; // ID of the send transaction associated with this one. Null if a transaction is a send
    @DatabaseField(dataType=DataType.BYTE_ARRAY)
    private byte[] senderSig; // Null if transaction is a send
    @DatabaseField
    private boolean pending;

    @DatabaseField
    private String timestamp;
    @DatabaseField(dataType=DataType.BYTE_ARRAY)
    private byte[] sig;
    @DatabaseField
    private String transactionHash;
    @DatabaseField
    private String previousTransaction;

    public Transaction() {

    }

    public Transaction(String id, Account from, Account to, int amount, String timestamp, String previousTransaction, byte[] sig) {
        this(id, from, to, amount, timestamp, true, false, previousTransaction, sig);
    }

    public Transaction(String id, Account from, Account to, int amount, String timestamp, boolean pending, boolean receiving,String previousTransaction, byte[] sig) {
        this.id = id;
        this.from = from;
        this.to = to;
        this.amount = amount;
        this.pending = pending;
        this.receiving = receiving;
        this.timestamp = timestamp;
        if (previousTransaction != null) {
            this.previousTransaction = previousTransaction;
        } else {
            // FIXME: Is this needed?
            this.previousTransaction = "000000";
        }
        this.sig = sig;

        try {
            MessageDigest digester = MessageDigest.getInstance("SHA-256");
            digester.update(sig);
            this.transactionHash = Base64.getEncoder().encodeToString(digester.digest());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        if (receiving) {
            this.owner = to;
        } else {
            this.owner = from;
        }
    }

    public static Transaction ReceiveTransaction(String id, Transaction transaction, String timestamp, String previousTransaction, byte[] sig) {
        Transaction receive = new Transaction(id, transaction.from, transaction.to, transaction.amount, timestamp, false, true, previousTransaction, sig);
        transaction.setPending(false);
        receive.setSenderSig(transaction.getSig());
        return receive;
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

    public void setId(String id) {
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public boolean isPending(){
        return this.pending;
    }

    public boolean isReceiving() {
        return receiving;
    }

    public void setReceiving(boolean receiving) {
        this.receiving = receiving;
    }

    public void setPending(boolean pending) {
        this.pending = pending;
    }

    public boolean isLast() {
        return last;
    }

    public void setLast(boolean last) {
        this.last = last;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getSig() {
        return sig;
    }

    public void setSig(byte[] sig) {
        this.sig = sig;
    }

    public String getPreviousTransaction() {
        return previousTransaction;
    }

    public void setPreviousTransaction(String previousTransaction) {
        this.previousTransaction = previousTransaction;
    }

    public String getTransactionHash() {
        return transactionHash;
    }

    public void setTransactionHash(String transactionHash) {
        this.transactionHash = transactionHash;
    }

    public Account getOwner() {
        return owner;
    }

    public void setOwner(Account owner) {
        this.owner = owner;
    }

    public byte[] getSenderSig() {
        return senderSig;
    }

    public void setSenderSig(byte[] senderSig) {
        this.senderSig = senderSig;
    }

    public int getSenderId() {
        return senderId;
    }

    public void setSenderId(int senderId) {
        this.senderId = senderId;
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
        if (!this.id.equals(other.id)) {
            return false;
        }
        if (!this.from.getKeyHash().equals(other.from.getKeyHash())){
            return false;
        }
        if (!this.to.getKeyHash().equals(other.to.getKeyHash())){
            return false;
        }
        if (this.amount != other.amount){
            return false;
        }
        if (this.pending != other.pending){
            return false;
        }
        if (!this.transactionHash.equals(other.transactionHash)){
            return false;
        }
        return true;
    }


    @Override
    public int compareTo(@NotNull Object o) {
        Transaction other = (Transaction) o;

        Integer thisIndex = Integer.parseInt(this.getId().substring(0, this.getId().indexOf("-")));
        Integer otherIndex = Integer.parseInt(other.getId().substring(0, other.getId().indexOf("-")));

        return thisIndex.compareTo(otherIndex);
    }
}
