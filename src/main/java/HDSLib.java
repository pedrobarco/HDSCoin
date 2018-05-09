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
import java.util.Arrays;
import java.util.Base64;
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
        	// TODO: How to properly get port?
            connectionSource = new JdbcConnectionSource("jdbc:h2:./db/" + databaseName + Application.port);
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

    public Account register(PublicKey key, String timestamp, byte[] sig) throws KeyAlreadyRegistered, TimestampNotFreshException, InvalidSignatureException, NullArgumentException {
        try {
			Date timeReceived = new Date();

        	checkNullKey(key);
			checkNullTimestamp(timestamp);
			checkNullSignature(sig);
        	
            Account account = new Account(key);
            if (accounts.queryForId(account.getKeyHash()) != null) {
                throw new KeyAlreadyRegistered("The following key is already registered: " + key);
            }

            if (!HDSCrypto.validateTimestamp(timeReceived, HDSCrypto.stringToDate(timestamp))) {
            	throw new TimestampNotFreshException("Timestamp not fresh");
            }
			Signature s = HDSCrypto.verifySignature(key);
			s.update(timestamp.getBytes());
            if(!s.verify(sig)){
            	throw new InvalidSignatureException("Signature not valid");
            }
            
            accounts.create(account);
            return account;
        } catch (SQLException | SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
		return null;
    }

    public Transaction sendAmount(String sourceKeyHash, String destKeyHash, int amount, String previousTransaction, String timestamp, byte[] sig) throws AccountNotFoundException, AccountInsufficientAmountException, TimestampNotFreshException, InvalidSignatureException, NullArgumentException, InvalidAmountException, SameSourceAndDestAccountException, InvalidKeyException, SignatureException, RepeatedTransactionException, WrongPreviousTransactionException {
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
        } else if (sourceKeyHash.equals(destKeyHash)) {
	    	throw new SameSourceAndDestAccountException();
	    }
        if (!HDSCrypto.validateTimestamp(timeReceived, HDSCrypto.stringToDate(timestamp))) {
        	throw new TimestampNotFreshException("Timestamp not fresh: " + timestamp);
		}

		Signature s = HDSCrypto.verifySignature(sourceAccount.getKey());
		s.update(sourceKeyHash.getBytes());
		s.update(destKeyHash.getBytes());
		s.update(BigInteger.valueOf(amount).toByteArray());
		s.update(previousTransaction.getBytes());
		s.update(timestamp.getBytes());
		if(!s.verify(sig)){
			throw new InvalidSignatureException("Signature not valid");
		}

		// Check for repeated transactions, verify the amount and then update it atomically
		synchronized (this) {
			if (getTransactionBySig(sig) != null) {
				throw new RepeatedTransactionException();
			}

			if (sourceAccount.getAmount() < amount) {
				throw new AccountInsufficientAmountException();
			}

			String actualPreviousTransactionHash = null;
			Transaction actualPreviousTransaction = null;
			try {
				if (transactions.queryBuilder().where().eq("owner_id", sourceKeyHash).query().size() > 0) {
					actualPreviousTransaction = transactions.queryBuilder().where().eq("last", true).and().eq("owner_id", sourceKeyHash).queryForFirst();
					actualPreviousTransactionHash = actualPreviousTransaction.getTransactionHash();
				}
			} catch (SQLException e) {
				e.printStackTrace();
				return null;
			}

			if(actualPreviousTransaction != null){
				if (!previousTransaction.equals(actualPreviousTransactionHash)){
					throw new WrongPreviousTransactionException(previousTransaction, actualPreviousTransactionHash);
				}
			}

			Transaction transaction = new Transaction(sourceAccount, destAccount, amount, timestamp, actualPreviousTransactionHash, sig);
			sourceAccount.addAmount(-amount);
			transaction.setLast(true);
			if (actualPreviousTransaction != null) {
				actualPreviousTransaction.setLast(false);
			}
			try {
				transactions.create(transaction);
				transactions.update(actualPreviousTransaction);
				accounts.update(sourceAccount);
				accounts.update(destAccount);
				return transaction;
			} catch (SQLException e) {
				e.printStackTrace();
			}
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
            pendingIncomingTransactions = transactions.queryBuilder().where().eq("pending", true).and().eq("receiving", false).and().eq("to_id", keyHash).query();
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return new AccountState(account.getKeyHash(), account.getAmount(), pendingIncomingTransactions);
    }

    public Transaction receiveAmount(int id, byte[] transactionSig, String previousTransaction, String timestamp, byte[] sig) throws TransactionNotFoundException, AccountInsufficientAmountException, InvalidKeyException, SignatureException, TimestampNotFreshException, InvalidSignatureException, NullArgumentException, TransactionAlreadyReceivedException, WrongPreviousTransactionException {
    	Date timeReceived = new Date();
		checkNullTimestamp(timestamp);
		checkNullSignature(sig);
        
        Transaction transaction = getTransaction(id);
        
        if (transaction == null) {
            throw new TransactionNotFoundException("Transaction not found");
        }

        if (!HDSCrypto.validateTimestamp(timeReceived, HDSCrypto.stringToDate(timestamp))) {
        	throw new TimestampNotFreshException("Timestamp not fresh");
		}
		if (!Arrays.equals(transaction.getSig(),transactionSig)){
        	throw new InvalidSignatureException("Sent transaction signature doesn't match transaction ID\n"+
					"Received: " +  new String(Base64.getEncoder().encode(transactionSig))+
					"\nExpected: " +  new String(Base64.getEncoder().encode(transaction.getSig())));
		}

		//Account sourceAccount = transaction.getFrom();
		Account destAccount = transaction.getTo();
		try {
			accounts.refresh(destAccount);
		} catch (SQLException e) {
			e.printStackTrace();
		}

		Signature s = HDSCrypto.verifySignature(destAccount.getKey());
		s.update(BigInteger.valueOf(id).toByteArray());
		s.update(transactionSig);
		s.update(previousTransaction.getBytes());
		s.update(timestamp.getBytes());
		if(!s.verify(sig)){
			throw new InvalidSignatureException("Signature not valid");
		}
		// Make sure the transaction wasn't already received and complete it atomically
		synchronized (this) {
			try {
				transactions.refresh(transaction);

				if (transactions.queryBuilder().where().eq("senderSig", transactionSig).query().size() != 0) {
					throw new TransactionAlreadyReceivedException("This transaction was already received: " + transaction.getId());
				}

				String actualPreviousTransactionHash = null;
				Transaction actualPreviousTransaction = null;
				try {
					if (transactions.queryBuilder().where().eq("owner_id", destAccount.getKeyHash()).query().size() > 0) {
						actualPreviousTransaction = transactions.queryBuilder().where().eq("last", true).and().eq("owner_id", destAccount.getKeyHash()).queryForFirst();
						actualPreviousTransactionHash = actualPreviousTransaction.getTransactionHash();
					}
				} catch (SQLException e) {
					e.printStackTrace();
					return null;
				}

				if(actualPreviousTransaction != null){
					if (!previousTransaction.equals(actualPreviousTransactionHash)){
						throw new WrongPreviousTransactionException(previousTransaction, actualPreviousTransactionHash); // TODO: Test this exception
					}
				}

				destAccount.addAmount(transaction.getAmount());
				Transaction newTransaction = Transaction.ReceiveTransaction(transaction, timestamp, previousTransaction, sig);
				newTransaction.setLast(true);
				if (actualPreviousTransaction != null) {
					actualPreviousTransaction.setLast(false);
				}

				transactions.update(transaction);
				transactions.update(actualPreviousTransaction);
				transactions.create(newTransaction);
				accounts.update(destAccount);
				return transaction;

				} catch (SQLException e) {
					e.printStackTrace();
				}
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

	public Transaction getTransactionBySig(byte[] sig) {
		try {
			List<Transaction> repeats = transactions.queryBuilder().where().eq("sig", sig).query();
			if (repeats.size() == 0) {
				return null;
			} else {
				return repeats.get(0);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

    public List<Transaction> getAccountTransactions(String keyHash){
		try {
			return transactions.queryBuilder().where().eq("owner_id", keyHash).query();
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

	private void checkNullTimestamp(String timestamp) throws NullArgumentException {
		if (timestamp == null) {
			throw new NullArgumentException("Null or empty timestamp");
		}
	}
}
