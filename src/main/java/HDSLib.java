import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.dao.ForeignCollection;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import domain.Account;
import domain.AccountState;
import domain.Transaction;
import exceptions.*;

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

    public Account register(String key, Date timestamp, byte[] sig) throws KeyAlreadyRegistered, InvalidKeySpecException, TimestampNotFreshException, InvalidSignatureException, NullArgumentException {
        try {
			Date timeReceived = new Date();

        	checkNullKey(key);
			checkNullTimestamp(timestamp);
			checkNullSignature(sig);
        	
            Account account = new Account(key);
            if (accounts.queryForId(account.getKeyHash()) != null) {
                throw new KeyAlreadyRegistered("The following key is already registered: " + key);
            }

            if (!HDSCrypto.validateTimestamp(timeReceived, timestamp)) {
            	throw new TimestampNotFreshException("Timestamp not fresh");
            }
            
            PublicKey pubKey = HDSCrypto.stringToPublicKey(key);
            if(!HDSCrypto.verifySignature(HDSCrypto.dateToString(timestamp).getBytes(), pubKey, sig)){
            	throw new InvalidSignatureException("Signature not valid");
            }
            
            accounts.create(account);
            return account;
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		return null;
    }

    public Transaction sendAmount(String sourceKey, String destKey, int amount, Date timestamp, byte[] sig) throws AccountNotFoundException, AccountInsufficientAmountException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, TimestampNotFreshException, InvalidSignatureException, ParseException, NullArgumentException, InvalidAmountException, SameSourceAndDestAccountException {
		Date timeReceived = new Date();

    	checkNullKey(sourceKey);
		checkNullKey(destKey);
		checkNullTimestamp(timestamp);
		checkNullSignature(sig);
		if (amount <= 0) {
			throw new InvalidAmountException();
		}
    	
    	Account sourceAccount = getAccount(sourceKey);
        Account destAccount = getAccount(destKey);

        if (sourceAccount == null) {
        	throw new AccountNotFoundException("Source account not found!");
        } else if (destAccount == null) {
            throw new AccountNotFoundException("Destination account not found!");
        } else if (sourceAccount.getAmount() < amount) {
            throw new AccountInsufficientAmountException("There is not enough money in your account");
        } else if (sourceKey.equals(destKey)) {
	    	throw new SameSourceAndDestAccountException("Can not send money to yourself");
	    }

        if (!HDSCrypto.validateTimestamp(timeReceived, timestamp)) {
        	throw new TimestampNotFreshException("Timestamp not fresh");
		}
        
        byte[] keyhashes = HDSCrypto.concatBytes(sourceKey.getBytes(), destKey.getBytes());
		byte[] hashAmount = HDSCrypto.concatBytes(keyhashes, BigInteger.valueOf(amount).toByteArray());
		byte[] content = HDSCrypto.concatBytes(hashAmount, HDSCrypto.dateToString(timestamp).getBytes());
		if(!HDSCrypto.verifySignature(content, HDSCrypto.stringToPublicKey(sourceAccount.getKey()), sig)){
			throw new InvalidSignatureException("Signature not valid");
		}
		
		//TODO: como verificar se a transaccao e unica?
        
        Transaction transaction = new Transaction(sourceAccount, destAccount, amount);
        sourceAccount.addAmount(-amount);
        try {
            transactions.create(transaction);
            accounts.update(sourceAccount);
            return transaction;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public AccountState checkAccount(String key) throws AccountNotFoundException, NullArgumentException {
    	checkNullKey(key);
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

    public Transaction receiveAmount(String sourceKey, String destKey, int id, Date timestamp, byte[] sig) throws AccountNotFoundException, TransactionNotFoundException, AccountInsufficientAmountException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException, TimestampNotFreshException, TransactionWrongKeyException, InvalidSignatureException, ParseException, NullArgumentException {
    	// TODO: Don't need sourceKey and destKey
    	Date timeReceived = new Date();
    	checkNullKey(sourceKey);
		checkNullKey(destKey);
		checkNullTimestamp(timestamp);
		checkNullSignature(sig);
    	
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

        if (!HDSCrypto.validateTimestamp(timeReceived, timestamp)) {
        	throw new TimestampNotFreshException("Timestamp not fresh");
		}
        
        byte[] keyhashs = HDSCrypto.concatBytes(sourceKey.getBytes(), destKey.getBytes());
		byte[] hashAmount = HDSCrypto.concatBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		byte[] content = HDSCrypto.concatBytes(hashAmount, HDSCrypto.dateToString(timestamp).getBytes());
		if(!HDSCrypto.verifySignature(content, HDSCrypto.stringToPublicKey(destAccount.getKey()), sig)){
			throw new InvalidSignatureException("Signature not valid");
		}
        
        destAccount.addAmount(transaction.getAmount());
        transaction.setPending(false);
        try {
            transactions.update(transaction);
            accounts.update(destAccount);
            return transaction;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public ForeignCollection<Transaction> audit(String key) throws AccountNotFoundException, NullArgumentException {
    	checkNullKey(key);
    	
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

	private void checkNullKey(String key) throws NullArgumentException {
		if (key == null || key.trim().equals("")) {
			throw new NullArgumentException("Null or empty key");
		}
	}

    private void checkNullSignature(byte[] sig) throws NullArgumentException {
		if (sig == null) {
			throw new NullArgumentException("Null or empty signature");
		}
	}

	private void checkNullTimestamp(Date timestamp) throws NullArgumentException {
		if (timestamp == null) {
			throw new NullArgumentException("Null or empty timestamp");
		}
	}
}
