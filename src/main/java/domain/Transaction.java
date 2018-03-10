package domain;

public class Transaction {
    public Account from;
    public Account to;
    public int amount;
    public int id;

    public Transaction(Account from, Account to, int amount, int id) {
        setFrom(from);
        setTo(to);
        setAmount(amount);
        setId(id);
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
}
