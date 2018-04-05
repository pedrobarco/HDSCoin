import com.j256.ormlite.dao.Dao;
import com.j256.ormlite.dao.DaoManager;
import com.j256.ormlite.jdbc.JdbcConnectionSource;
import com.j256.ormlite.support.ConnectionSource;
import com.j256.ormlite.table.TableUtils;
import domain.Account;
import domain.AccountState;
import domain.Transaction;
import exceptions.*;

import java.math.BigInteger;
import java.security.*;
import java.sql.SQLException;
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

    public Account register(PublicKey key, Date timestamp, byte[] sig) throws KeyAlreadyRegistered, TimestampNotFreshException, InvalidSignatureException, NullArgumentException {
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
			Signature s = HDSCrypto.verifySignature(key);
			s.update(HDSCrypto.dateToString(timestamp).getBytes());
            if(!s.verify(sig)){
            	throw new InvalidSignatureException("Signature not valid");
            }
            
            accounts.create(account);
            return account;
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		catch (SignatureException e) {
			e.printStackTrace();
		}
		return null;
    }

    public Transaction sendAmount(String sourceKeyHash, String destKeyHash, int amount, Date timestamp, byte[] sig) throws AccountNotFoundException, AccountInsufficientAmountException, TimestampNotFreshException, InvalidSignatureException, NullArgumentException, InvalidAmountException, SameSourceAndDestAccountException, InvalidKeyException, SignatureException {
		Date timeReceived = new Date();

		checkNullKeyHash(sourceKeyHash);
		checkNullKeyHash(destKeyHash);
		checkNullTimestamp(timestamp);
		checkNullSignature(sig);
		if (amount <= 0) {
			throw new InvalidAmountException();
		}
    	
    	Account sourceAccount = getAccount(sourceKeyHash);
        Account destAccount = getAccount(destKeyHash);

        if (sourceAccount == null) {
        	throw new AccountNotFoundException("Source account not found: " + sourceKeyHash);
        } else if (destAccount == null) {
            throw new AccountNotFoundException("Destination account not found: " + destKeyHash);
        } else if (sourceAccount.getAmount() < amount) {
            throw new AccountInsufficientAmountException();
        } else if (sourceKeyHash.equals(destKeyHash)) {
	    	throw new SameSourceAndDestAccountException();
	    }

        if (!HDSCrypto.validateTimestamp(timeReceived, timestamp)) {
        	throw new TimestampNotFreshException("Timestamp not fresh: " + timestamp);
		}

		Signature s = HDSCrypto.verifySignature(sourceAccount.getKey());
		s.update(sourceKeyHash.getBytes());
		s.update(destKeyHash.getBytes());
		s.update(BigInteger.valueOf(amount).toByteArray());
		s.update(HDSCrypto.dateToString(timestamp).getBytes());
		if(!s.verify(sig)){
			throw new InvalidSignatureException("Signature not valid");
		}
		
		//TODO: como verificar se a transaccao e unica?
        
        Transaction transaction = new Transaction(sourceAccount, destAccount, amount);
        sourceAccount.addAmount(-amount);
        try {
            transactions.create(transaction);
            accounts.update(sourceAccount);
			accounts.update(destAccount);
            return transaction;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    public AccountState checkAccount(String keyHash) throws AccountNotFoundException, NullArgumentException {
		checkNullKeyHash(keyHash);
    	Account account = getAccount(keyHash);
        
        if (account == null) {
            throw new AccountNotFoundException("Account not found: " + keyHash);
        }
        List<Transaction> pendingIncomingTransactions= null;
        try {
            pendingIncomingTransactions = transactions.queryBuilder().where().eq("pending", true).and().eq("to_id", keyHash).query();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return new AccountState(account.getKeyHash(), account.getAmount(), pendingIncomingTransactions);
    }

    public Transaction receiveAmount(int id, Date timestamp, byte[] sig) throws TransactionNotFoundException, AccountInsufficientAmountException, InvalidKeyException, SignatureException, TimestampNotFreshException, InvalidSignatureException, NullArgumentException {
    	Date timeReceived = new Date();
		checkNullTimestamp(timestamp);
		checkNullSignature(sig);
        
        Transaction transaction = getTransaction(id);
        
        if (transaction == null) {
            throw new TransactionNotFoundException("Transaction not found");
        }

        if (!HDSCrypto.validateTimestamp(timeReceived, timestamp)) {
        	throw new TimestampNotFreshException("Timestamp not fresh");
		}

		Account sourceAccount = transaction.getFrom();
		Account destAccount = transaction.getTo();
		try {
			accounts.refresh(destAccount);
		} catch (SQLException e) {
			e.printStackTrace();
		}

		Signature s = HDSCrypto.verifySignature(destAccount.getKey());
		s.update(BigInteger.valueOf(id).toByteArray());
		s.update(HDSCrypto.dateToString(timestamp).getBytes());
		if(!s.verify(sig)){
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

    public List<Transaction> audit(String keyHash) throws AccountNotFoundException, NullArgumentException {
		checkNullKeyHash(keyHash);
    	
    	Account account = null;
        try {
            account = accounts.queryForId(keyHash);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        if (account == null) {
            throw new AccountNotFoundException("Account not found: " + keyHash);
        }
        return getAccountTransactions(keyHash);
    }

    public Account getAccount(String keyHash) {
        Account account = null;
        try {
            account = accounts.queryForId(keyHash);
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

    public List<Transaction> getAccountTransactions(String keyHash){
		try {
			return transactions.queryBuilder().where().eq("from_id", keyHash).or().eq("to_id", keyHash).query();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	private void checkNullKeyHash(String key) throws NullArgumentException {
		if (key == null || key.trim().equals("")) {
			throw new NullArgumentException("Null or empty key hash");
		}
	}

	private void checkNullKey(Key key) throws NullArgumentException {
		if (key == null) {
			throw new NullArgumentException("Null key");
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
