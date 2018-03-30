import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.dao.ForeignCollection;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;

import domain.Account;
import domain.AccountState;
import domain.Transaction;
import exceptions.AccountInsufficientAmountException;
import exceptions.AccountNotFoundException;
import exceptions.ArgumentsException;
import exceptions.InvalidSignatureException;
import exceptions.KeyAlreadyRegistered;
import exceptions.TimestampNotFreshException;
import exceptions.TransactionNotFoundException;
import exceptions.TransactionWrongKeyException;


public class HDSLib {
    private static HDSLib instance = null;
    private Dao<Account, String> accounts;
    private Dao<Transaction, Integer> transactions;
    private ConnectionSource connectionSource;

    private HDSLib(String databaseName) {
        connectionSource = null;
        try {
            connectionSource = new JdbcConnectionSource("jdbc:h2:./db/" + databaseName);
            accounts = DaoManager.createDao(connectionSource, Account.class);
            transactions = DaoManager.createDao(connectionSource, Transaction.class);
        } catch (SQLException e) {
            e.printStackTrace();
        }

        try {
            TableUtils.createTable(connectionSource, Account.class);
            TableUtils.createTable(connectionSource, Transaction.class);
        } catch (SQLException e) {
            System.out.println("Table already exists, skipping...");
        }
    }

    public static HDSLib getInstance() {
        if (instance == null) {
            instance = new HDSLib("database");
        }
        return instance;
    }

    public static HDSLib getTestingInstance() {
        if (instance == null) {
            instance = new HDSLib("test");
        }
        return instance;
    }

    public static void forceReset() {
        // For testing purposes
        instance.destroy();
        instance = null;
    }

    public void destroy() {
        try {
            connectionSource.close();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void register(String stringKey, byte[] sig, byte[] timestamp) throws KeyAlreadyRegistered, InvalidKeySpecException, TimestampNotFreshException, InvalidSignatureException, ParseException, ArgumentsException {
        try {
        	Date timeReceived = new Date();
        	checkRegisterArguments(stringKey, sig, timestamp);
        	
            Account account = new Account(stringKey);
            if (accounts.queryForId(account.getKeyHash()) != null) {
                throw new KeyAlreadyRegistered("The following key is already registered: " + stringKey);
            }

            Date time = HDSCrypto.convertByteArrayToDate(timestamp);
            if (!HDSCrypto.validateTimestamp(timeReceived, time)) {
            	throw new TimestampNotFreshException("Timestamp not fresh");
            }
            
            PublicKey pubKey = HDSCrypto.stringToPublicKey(stringKey);
            if(!HDSCrypto.verifySignature(timestamp, pubKey, sig)){
            	throw new InvalidSignatureException("Signature not valid");
            }
            
            accounts.create(account);
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
    }

    public void sendAmount(String sourceKey, String destKey, int amount, byte[] timestamp, byte[] sig) throws AccountNotFoundException, AccountInsufficientAmountException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, TimestampNotFreshException, InvalidSignatureException, ParseException, ArgumentsException {
    	Date timeReceived = new Date();
    	checksendAmountArguments(sourceKey, destKey, amount, timestamp, sig);
    	
    	Account sourceAccount = getAccount(sourceKey);
        Account destAccount = getAccount(destKey);

        if (sourceAccount == null) {
        	throw new AccountNotFoundException("Source account not found!");
        } else if (destAccount == null) {
            throw new AccountNotFoundException("Destination account not found!");
        } else if (sourceAccount.getAmount() < amount) {
            throw new AccountInsufficientAmountException("There is not enough money in your account");
        }
        
        Date time = HDSCrypto.convertByteArrayToDate(timestamp);
        if (!HDSCrypto.validateTimestamp(timeReceived, time)) {
        	throw new TimestampNotFreshException("Timestamp not fresh");
		}
        
        byte[] keyhashs = HDSCrypto.concacBytes(sourceKey.getBytes(), destKey.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		byte[] content = HDSCrypto.concacBytes(hashAmount, timestamp);
		if(!HDSCrypto.verifySignature(content, HDSCrypto.stringToPublicKey(sourceAccount.getKey()), sig)){
			throw new InvalidSignatureException("Signature not valid");
		}
		
		//TODO: como verificar se a transaccao e unica?
        
        Transaction transaction = new Transaction(sourceAccount, destAccount, amount);
        sourceAccount.addAmount(-amount);
        try {
            transactions.create(transaction);
            accounts.update(sourceAccount);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public AccountState checkAccount(String key) throws AccountNotFoundException, ArgumentsException {
    	checkArguments(key);
    	Account account = getAccount(key);
        
        if (account == null) {
            throw new AccountNotFoundException("Account not found!");
        }
        List<Transaction> pendingIncomingTransactions= null;
        try {
            pendingIncomingTransactions = transactions.queryBuilder().where().eq("pending", true).and().eq("to_id",key).query();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return new AccountState(account.getKey(), account.getAmount(), pendingIncomingTransactions);
    }

    public void receiveAmount(String sourceKey, String destKey, int id, byte[] timestamp, byte[] sig) throws AccountNotFoundException, TransactionNotFoundException, AccountInsufficientAmountException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, TimestampNotFreshException, TransactionWrongKeyException, InvalidSignatureException, ParseException, ArgumentsException {
    	Date timeReceived = new Date();
    	checkReceiveAmountArguments(sourceKey, destKey, id, timestamp, sig);
    	
    	Account sourceAccount = getAccount(sourceKey);
        Account destAccount = getAccount(destKey);
        
        if (sourceAccount == null) {
            throw new AccountNotFoundException("Source account not found!");
        } else if (destAccount == null) {
            throw new AccountNotFoundException("Destination account not found!");
        }
        
        Transaction transaction = getTransaction(id);
        
        if (transaction == null) {
            throw new TransactionNotFoundException("Transaction not found");
        } 
        
        if(!transaction.getFrom().getKeyHash().equals(sourceKey)){
			throw new TransactionWrongKeyException("Wrong source transaction");
		}
		
		if(!transaction.getTo().getKeyHash().equals(destKey)){
			throw new TransactionWrongKeyException("Wrong destination transaction");
		}
        
		Date time = HDSCrypto.convertByteArrayToDate(timestamp);
        if (!HDSCrypto.validateTimestamp(timeReceived, time)) {
        	throw new TimestampNotFreshException("Timestamp not fresh");
		}
        
        byte[] keyhashs = HDSCrypto.concacBytes(sourceKey.getBytes(), destKey.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		byte[] content = HDSCrypto.concacBytes(hashAmount, timestamp);
		if(!HDSCrypto.verifySignature(content, HDSCrypto.stringToPublicKey(destAccount.getKey()), sig)){
			throw new InvalidSignatureException("Signature not valid");
		}
        
        destAccount.addAmount(transaction.getAmount());
        transaction.setPending(false);
        try {
            transactions.update(transaction);
            accounts.update(destAccount);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public ForeignCollection<Transaction> audit(String key) throws AccountNotFoundException, ArgumentsException {
    	checkArguments(key);
    	
    	Account account = null;
        try {
            account = accounts.queryForId(key);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        if (account == null) {
            throw new AccountNotFoundException("Account not found!");
        }
        return account.getTransactions();
    }

    public Account getAccount(String key) {
        Account account = null;
        try {
            account = accounts.queryForId(key);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return account;
    }

    public Transaction getTransaction(int id) {
        Transaction transaction = null;
        try {
            transaction = transactions.queryForId(id);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return transaction;
    }
    
    private void checkRegisterArguments(String stringKey, byte[] sig, byte[] timestamp) throws ArgumentsException {
		if (stringKey == null || sig == null || timestamp == null || stringKey.trim().equals("")) {
			throw new ArgumentsException("Null or empty string is not accepted");
		}
	}

    private void checksendAmountArguments(String sourceKey, String destKey,  int amount, byte[] timestamp, byte[] sig) throws ArgumentsException {
    	if (sourceKey == null || destKey == null || sig == null || timestamp == null || amount <=0 || sourceKey.trim().equals("") || destKey.trim().equals("")) {
    		throw new ArgumentsException("Null or empty string is not accepted");
    	}
    }

    private void checkArguments(String stringKey) throws ArgumentsException {
    	if (stringKey == null || stringKey.trim().equals("")) {
    		throw new ArgumentsException("Null or empty string is not accepted");
    	}
    }

    private void checkReceiveAmountArguments(String sourceKey, String destKey, int id, byte[] timestamp, byte[] sig) throws ArgumentsException {
    	if (sourceKey == null || destKey == null || sig == null || timestamp == null || id <=0 || sourceKey.trim().equals("") || destKey.trim().equals("")) {
    		throw new ArgumentsException("Null or empty string is not accepted");
    	}
    }
}
