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
import exceptions.KeyAlreadyRegistered;
import exceptions.TransactionNotFoundException;

import javax.crypto.SealedObject;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLException;
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

    public void register(String stringKey, byte[] sig, byte[] timestamp) throws KeyAlreadyRegistered, InvalidKeySpecException {
        try {
            Account account = new Account(stringKey);
            if (accounts.queryForId(account.getKeyHash()) != null) {
                throw new KeyAlreadyRegistered("The following key is already registered: " + stringKey);
            }

            Date time = HDSCrypto.convertByteArrayToDate(timestamp);
            if (Math.abs(HDSCrypto.timestampToDate(HDSCrypto.dateFormat.format(time)).compareTo(new Date())) >= 60) {
                // TODO: Proper exception
                System.out.println("Timestamp not fresh");
            }
            
            PublicKey pubKey = HDSCrypto.stringToPublicKey(stringKey); //TODO: ver melhor a convercao de string para publicKey
            if(!HDSCrypto.verifySignature(timestamp, pubKey, sig)){
            	System.out.println("Signature has been changed");
            }
            
            accounts.create(account);
        } catch (SQLException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

    public void sendAmount(String sourceKey, String destKey,  int amount, byte[] timestamp, byte[] sig) throws AccountNotFoundException, AccountInsufficientAmountException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, InvalidKeySpecException {
        Account sourceAccount = null;
        Account destAccount = null;
        try {
            sourceAccount = accounts.queryForId(sourceKey);
            destAccount = accounts.queryForId(destKey);
        } catch (SQLException e) {
            e.printStackTrace();
        }

        if (sourceAccount == null) {
            throw new AccountNotFoundException("Source account not found!");
        } else if (destAccount == null) {
            throw new AccountNotFoundException("Destination account not found!");
        } else if (sourceAccount.getAmount() < amount) {
            throw new AccountInsufficientAmountException();
        }
        
        byte[] keyhashs = HDSCrypto.concacBytes(sourceKey.getBytes(), destKey.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		byte[] content = HDSCrypto.concacBytes(hashAmount, timestamp);
		if(!HDSCrypto.verifySignature(content, HDSCrypto.stringToPublicKey(sourceAccount.getKey()), sig)){
			//TODO: exception
			System.out.println("Signature not valid");
		}
		
		//TODO: como verificar se a transaccao e unica?
		
        /*if (Math.abs(HDSCrypto.timestampToDate(new String(timestamp)).compareTo(new Date())) >= 60) {
            // TODO: Proper exception
            System.out.println("Timestamp not fresh");
        }*/
        
        Transaction transaction = new Transaction(sourceAccount, destAccount, amount);
        sourceAccount.addAmount(-amount);
        try {
            transactions.create(transaction);
            accounts.update(sourceAccount);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public AccountState checkAccount(String key) throws AccountNotFoundException {
        Account account = null;
        try {
            account = accounts.queryForId(key);
        } catch (SQLException e) {
            e.printStackTrace();
        }
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

    public void receiveAmount(String sourceKey, String destKey, int id) throws AccountNotFoundException, TransactionNotFoundException, AccountInsufficientAmountException {
    	//TODO: falta crypto
    	Account sourceAccount = null;
        Account destAccount = null;
        try {
            sourceAccount = accounts.queryForId(sourceKey);
            destAccount = accounts.queryForId(destKey);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        if (sourceAccount == null) {
            throw new AccountNotFoundException("Source account not found!");
        } else if (destAccount == null) {
            throw new AccountNotFoundException("Destination account not found!");
        }
        Transaction transaction = null;
        try {
            transaction = transactions.queryForId(id);
        } catch (SQLException e) {
            e.printStackTrace();
        }
        if (transaction == null) {
            throw new TransactionNotFoundException();
        } else if (sourceAccount.getAmount() < transaction.getAmount()) {
            throw new AccountInsufficientAmountException();
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

    public ForeignCollection<Transaction> audit(String key) throws AccountNotFoundException {
    	//TODO: falta crypto
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
}
