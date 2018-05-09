package client.domain;

public class Transaction {
    private int id;
    private String from;
    private String to;
    private int amount;

    private String signature;
    private String transactionHash;

    public Transaction(int id, String from, String to, int amount, String signature, String transactionHash){
        this.id = id;
        this.from = from;
        this.to = to;
        this.amount = amount;
        this.signature = signature;
        this.transactionHash = transactionHash;
    }

    @Override
    public String toString() {
        return "Transaction " + id + "\n" +
                "- From: " + from + "\n" +
                "- To: " + to + "\n" +
                "- Amount: " + amount + "\n" +
                "- Signature: " + signature + "\n" +
                "- Transaction Hash: " + transactionHash + "\n";
    }

    public String getTransactionHash(){
        return transactionHash;
    }
    public String getSignature() {
        return signature;
    }
}
