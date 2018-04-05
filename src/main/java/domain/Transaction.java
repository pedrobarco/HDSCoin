package domain;

import com.j256.ormlite.field.DataType;
import com.j256.ormlite.field.DatabaseField;
import com.j256.ormlite.table.DatabaseTable;

import java.io.Serializable;
import java.util.Date;

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
    @DatabaseField(dataType = DataType.DATE)
    private Date sentTimestamp;
    @DatabaseField(dataType = DataType.DATE)
    private Date receivedTimestamp;
    @DatabaseField(dataType=DataType.BYTE_ARRAY)
    private byte[] senderSig;
    @DatabaseField(dataType=DataType.BYTE_ARRAY)
    private byte[] receiverSig;

    public Transaction() {

    }

    public Transaction(Account from, Account to, int amount, Date timestamp, byte[] sig) {
        this(from, to, amount, timestamp, true, sig);
    }

    public Transaction(Account from, Account to, int amount, Date timestamp, boolean pending, byte[] sig) {
        this.from = from;
        this.to = to;
        this.amount = amount;
        this.pending = pending;
        this.sentTimestamp = timestamp;
        this.senderSig = sig;
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

    public Date getSentTimestamp() {
        return sentTimestamp;
    }

    public void setSentTimestamp(Date sentTimestamp) {
        this.sentTimestamp = sentTimestamp;
    }

    public Date getReceivedTimestamp() {
        return receivedTimestamp;
    }

    public void setReceivedTimestamp(Date receivedTimestamp) {
        this.receivedTimestamp = receivedTimestamp;
    }

    public byte[] getSenderSig() {
        return senderSig;
    }

    public void setSenderSig(byte[] senderSig) {
        this.senderSig = senderSig;
    }

    public byte[] getReceiverSig() {
        return receiverSig;
    }

    public void setReceiverSig(byte[] receiverSig) {
        this.receiverSig = receiverSig;
    }

    public void complete(Date timestamp, byte[] sig){
        this.pending = false;
        this.receivedTimestamp = timestamp;
        this.receiverSig = sig;
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
