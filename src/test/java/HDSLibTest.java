import static java.util.Base64.getEncoder;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Calendar;
import java.util.Date;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

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

public class HDSLibTest {
	private HDSLib hdsLib;

	private static PublicKey pubEC1;
	private static PrivateKey privEC1;
	private static PublicKey pubEC2;
	private static PrivateKey privEC2;
	private static PublicKey pubEC3;
	private static PrivateKey privEC3;
	
	@BeforeClass
	public static void setUpAll() {
		System.setProperty("com.j256.ormlite.logger.type", "LOCAL");
		System.setProperty("com.j256.ormlite.logger.level", "ERROR");
		
		
		KeyPairGenerator keyGen = null;
		SecureRandom random = null;
		try {
			keyGen = KeyPairGenerator.getInstance("EC", "SunEC");
			random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		} catch (NoSuchAlgorithmException | NoSuchProviderException e1) {
			e1.printStackTrace();
		}
		keyGen.initialize(224, random);
		
		KeyPair ec = keyGen.generateKeyPair();
		pubEC1 = ec.getPublic();
		privEC1 = ec.getPrivate();
		
		ec = keyGen.generateKeyPair();
		pubEC2 = ec.getPublic();
		privEC2 = ec.getPrivate();

		ec = keyGen.generateKeyPair();
		pubEC3 = ec.getPublic();
		privEC3 = ec.getPrivate();
		
		
		// Generate 4 key pairs for testing
		/*
		KeyPairGenerator keyGen = null;
		SecureRandom random = null;
		try {
			keyGen = KeyPairGenerator.getInstance("RSA");
			random = SecureRandom.getInstance("SHA1PRNG");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keyGen.initialize(1024,  random);
		KeyPair pair = keyGen.generateKeyPair();
		pubkey1 = new String(Base64.getEncoder().encode(pair.getPublic().getEncoded()));
		privkey1 = new String(Base64.getEncoder().encode(pair.getPrivate().getEncoded()));
		pair = keyGen.generateKeyPair();
		pubkey2 = new String(Base64.getEncoder().encode(pair.getPublic().getEncoded()));
		privkey2 = new String(Base64.getEncoder().encode(pair.getPrivate().getEncoded()));
		pair = keyGen.generateKeyPair();
		pubkey3 = new String(Base64.getEncoder().encode(pair.getPublic().getEncoded()));
		privkey3 = new String(Base64.getEncoder().encode(pair.getPrivate().getEncoded()));
		pair = keyGen.generateKeyPair();
		pubkey4 = new String(Base64.getEncoder().encode(pair.getPublic().getEncoded()));
		privkey4 = new String(Base64.getEncoder().encode(pair.getPrivate().getEncoded()));*/
	}

	@Before
	public void setUp() throws Exception {
		hdsLib = HDSLib.getTestingInstance();
	}

	@After
	public void tearDown() throws Exception {
		HDSLib.forceReset();
		Files.deleteIfExists(Paths.get("./db/test.mv.db"));
		Files.deleteIfExists(Paths.get("./db/test.trace.db"));
	}

	private static String hashKey(String key) {
		MessageDigest digester = null;
		try {
			digester = MessageDigest.getInstance("SHA-256"); //TODO
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		digester.update(key.getBytes());
		return getEncoder().encodeToString(digester.digest());
	}

	@Test
	public void registerSuccess() throws Exception {
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		
		//SealedObject timestamp1 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey1), timestamp);
		//SealedObject timestamp2 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey2), timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		Account a1 = hdsLib.getAccount(keyhash1);
		Account a2 = hdsLib.getAccount(keyhash2);
		assertNotNull(a1);
		assertNotNull(a2);
		
		assertEquals(a1.getKey(), stringPubEC1);
		assertEquals(a2.getKey(), stringPubEC2);
		assertNotEquals(stringPubEC1, stringPubEC2);
		
		assertEquals(a1.getKeyHash(), keyhash1);
		assertEquals(a2.getKeyHash(), keyhash2);
		assertNotEquals(keyhash1, keyhash2);
		
		assertEquals(a1.getAmount(), 100);
		assertEquals(a2.getAmount(), 100);
		
		assertEquals(a1.getTransactions().size(), 0);
		assertEquals(a2.getTransactions().size(), 0);
	}


	@Test
	public void checkAccountSuccess() throws Exception {
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		
		byte[] sigRegister1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sigRegister2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		//SealedObject timestamp1 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey1), timestamp);
		//SealedObject timestamp2 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey2), timestamp);
		hdsLib.register(stringPubEC1, sigRegister1, byteTimestamp);
		hdsLib.register(stringPubEC2, sigRegister2, byteTimestamp);

		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date newTimestamp = HDSCrypto.createTimestamp();
		byte[] newByteTimestamp = HDSCrypto.convertDateToByteArray(newTimestamp);
		byte[] content = HDSCrypto.concacBytes(hashAmount, newByteTimestamp);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, newByteTimestamp, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash1);
		assertNotNull(state);
		assertEquals(state.getAmount(), 70);
		assertEquals(state.getPendingTransactions().size(), 0);
		
		Account a1 = hdsLib.getAccount(keyhash1);
		assertNotNull(a1);
		assertEquals(a1.getAmount(), state.getAmount());
		
		state = hdsLib.checkAccount(keyhash2);
		assertNotNull(state);
		assertEquals(state.getAmount(), 100);
		assertEquals(state.getPendingTransactions().size(), 1);
		
		Account a2 = hdsLib.getAccount(keyhash2);
		assertNotNull(a2);
		assertEquals(a2.getAmount(), state.getAmount());
	}
	
	@Test
	public void receiveSuccess() throws Exception {
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		
		byte[] sigRegister1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sigRegister2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		//SealedObject timestamp1 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey1), timestamp);
		//SealedObject timestamp2 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey2), timestamp);
		hdsLib.register(stringPubEC1, sigRegister1, byteTimestamp);
		hdsLib.register(stringPubEC2, sigRegister2, byteTimestamp);
		
		AccountState state = hdsLib.checkAccount(keyhash1);
		assertNotNull(state);
		assertEquals(state.getAmount(), 100);
		assertEquals(state.getPendingTransactions().size(), 0);

		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		state = hdsLib.checkAccount(keyhash1);
		assertNotNull(state);
		assertEquals(state.getAmount(), 40);
		assertEquals(state.getPendingTransactions().size(), 0);
		
		Account a1 = hdsLib.getAccount(keyhash1);
		assertNotNull(a1);
		assertEquals(state.getAmount(), a1.getAmount());
		
		state = hdsLib.checkAccount(keyhash2);
		assertNotNull(state);
		assertEquals(state.getAmount(), 100);
		assertEquals(state.getPendingTransactions().size(), 1);
		
		Account a2 = hdsLib.getAccount(keyhash2);
		assertNotNull(a2);
		assertEquals(state.getAmount(), a2.getAmount());
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash1, keyhash2, id, byteTimestamp3, sigReceiveAmount);
		state = hdsLib.checkAccount(keyhash1);
		a1 = hdsLib.getAccount(keyhash1);
		assertNotNull(a1);
		assertNotNull(state);
		assertEquals(state.getAmount(), 40);
		assertEquals(state.getPendingTransactions().size(), 0);
		assertEquals(state.getAmount(), a1.getAmount());
		
		state = hdsLib.checkAccount(keyhash2);
		a2 = hdsLib.getAccount(keyhash2);
		assertNotNull(a2);
		assertNotNull(state);
		assertEquals(state.getAmount(), 160);
		assertEquals(state.getPendingTransactions().size(), 0);
		assertEquals(state.getAmount(), a2.getAmount());
	}

	@Test
	public void SendAmountSuccess() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String stringPubEC3 = HDSCrypto.publicKeyToString(pubEC3);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		String keyhash3 = hashKey(stringPubEC3);
		int amount = 100;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sigRegister1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sigRegister2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		byte[] sigRegister3 = HDSCrypto.createSignatureEC(byteTimestamp, privEC3);
		hdsLib.register(stringPubEC1, sigRegister1, byteTimestamp);
		hdsLib.register(stringPubEC2, sigRegister2, byteTimestamp);
		hdsLib.register(stringPubEC3, sigRegister3, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		byte[] sigSendAmount1 = HDSCrypto.createSignatureEC(content, privEC1);
		
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount1);
		
		AccountState state = hdsLib.checkAccount(keyhash2);
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		byte[] sigReceiveAmount1 = HDSCrypto.createSignatureEC(content2, privEC2);
		
		hdsLib.receiveAmount(keyhash1, keyhash2, id, byteTimestamp3, sigReceiveAmount1);
		
		amount = 30;
		keyhashs = HDSCrypto.concacBytes(keyhash3.getBytes(), keyhash1.getBytes());
		hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp4 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp4 = HDSCrypto.convertDateToByteArray(timestamp4);
		content = HDSCrypto.concacBytes(hashAmount, byteTimestamp4);
		byte[] sigSendAmount2 = HDSCrypto.createSignatureEC(content, privEC3);
		
		hdsLib.sendAmount(keyhash3, keyhash1, amount, byteTimestamp4, sigSendAmount2);
		
		state = hdsLib.checkAccount(keyhash1);
		id = state.getPendingTransactions().get(0).getId();	
		hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp5 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp5 = HDSCrypto.convertDateToByteArray(timestamp5);
		byte[] content3 = HDSCrypto.concacBytes(hashID, byteTimestamp5);
		byte[] sigReceiveAmount2 = HDSCrypto.createSignatureEC(content3, privEC1);
		
		hdsLib.receiveAmount(keyhash3, keyhash1, id, byteTimestamp5, sigReceiveAmount2);
		
		keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp6 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp6 = HDSCrypto.convertDateToByteArray(timestamp6);
		content = HDSCrypto.concacBytes(hashAmount, byteTimestamp6);
		byte[] sigSendAmount3 = HDSCrypto.createSignatureEC(content, privEC1);
		
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp6, sigSendAmount3);
		
		state = hdsLib.checkAccount(keyhash2);
		id = state.getPendingTransactions().get(0).getId();	
		hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp7 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp7 = HDSCrypto.convertDateToByteArray(timestamp7);
		byte[] content4 = HDSCrypto.concacBytes(hashID, byteTimestamp7);
		byte[] sigReceiveAmount3 = HDSCrypto.createSignatureEC(content4, privEC2);
		
		hdsLib.receiveAmount(keyhash1, keyhash2, id, byteTimestamp7, sigReceiveAmount3);
		
		AccountState state1 = hdsLib.checkAccount(keyhash1);
		AccountState state2 = hdsLib.checkAccount(keyhash2);
		AccountState state3 = hdsLib.checkAccount(keyhash3);
		Account a1 = hdsLib.getAccount(keyhash1);
		Account a2 = hdsLib.getAccount(keyhash2);
		Account a3 = hdsLib.getAccount(keyhash3);
		assertEquals(a1.getKeyHash(), keyhash1);
		assertEquals(a2.getKeyHash(), keyhash2);
		assertEquals(a3.getKeyHash(), keyhash3);
		assertNotNull(state1);
		assertNotNull(state2);
		assertNotNull(state3);
		assertNotNull(a1);
		assertNotNull(a2);
		assertNotNull(a3);
		assertEquals(state1.getAmount(), 0);
		assertEquals(state1.getPendingTransactions().size(), 0);		
		assertEquals(state1.getAmount(), a1.getAmount());
		assertEquals(a1.getTransactions().size(), hdsLib.audit(keyhash1).size());
		for(Transaction t : hdsLib.audit(keyhash1)){
			assertEquals(t.getTo().getKeyHash(), keyhash2);
		}
		
		assertEquals(state2.getAmount(), 230);
		assertEquals(state2.getPendingTransactions().size(), 0);		
		assertEquals(state2.getAmount(), a2.getAmount());
		assertEquals(a2.getTransactions().size(), hdsLib.audit(keyhash2).size());
		
		assertEquals(state3.getAmount(), 70);
		assertEquals(state3.getPendingTransactions().size(), 0);
		assertEquals(state3.getAmount(), a3.getAmount());
		assertEquals(a3.getTransactions().size(), hdsLib.audit(keyhash3).size());
		for(Transaction t : hdsLib.audit(keyhash3)){
			assertEquals(t.getTo().getKeyHash(), keyhash1);
		}
	}
	
	@Test(expected = KeyAlreadyRegistered.class)
	public void registerExistingAccount() throws Exception {
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC, sig, byteTimestamp);
		hdsLib.register(stringPubEC, sig, byteTimestamp);
	}

	@Test(expected = ArgumentsException.class)
	public void registerNullKey() throws Exception {
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(null, sig, byteTimestamp);
	}

	@Test(expected = ArgumentsException.class)
	public void registerNullSig() throws Exception {
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		hdsLib.register(stringPubEC, null, byteTimestamp);
	}

	@Test(expected = ArgumentsException.class)
	public void registerNullTimestamp() throws Exception {
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC, sig, null);
	}

	@Test(expected = ArgumentsException.class)
	public void registerEmptyKey() throws Exception {
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register("", sig, byteTimestamp);
	}

	@Test(expected = ArgumentsException.class)
	public void registerBlankKey() throws Exception {
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register("   ", sig, byteTimestamp);
	}
	
	@Test(expected = TimestampNotFreshException.class)
	public void registerWrongTimestamp() throws Exception{
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		
		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.DATE, 2);
		Date timestamp = c.getTime();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC, sig, byteTimestamp);
	}
	
	@Test(expected = InvalidSignatureException.class)
	public void registerWrongSignature() throws Exception{
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		
		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.SECOND, 2);
		Date changeTimestamp = c.getTime();
		byte[] changeByteTimestamp = HDSCrypto.convertDateToByteArray(changeTimestamp);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC, sig, changeByteTimestamp);
	}
	
	@Test(expected = AccountNotFoundException.class)
	public void sendAmountSourceAccountNotFound() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC2, sig, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC2);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
	}
	
	@Test(expected = AccountNotFoundException.class)
	public void sendAmountDestinationAccountNotFound() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
	}

	@Test(expected = AccountInsufficientAmountException.class)
	public void sendAmountAccountNotEnough() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 100;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);

		amount = 30;
		byte[] hashAmount2 = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashAmount2, byteTimestamp3);
		
		byte[] sigSendAmount2 = HDSCrypto.createSignatureEC(content2, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp3, sigSendAmount2);
	}
	
	@Test(expected = TimestampNotFreshException.class)
	public void sendAmountWrongTimestamp() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.DATE, 2);
		Date timestamp2 = c.getTime();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
	}

	@Test(expected = InvalidSignatureException.class)
	public void sendAmountWrongSig() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		int changeAmount = 31;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(changeAmount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void sendAmountNullSourceKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(null, keyhash2, amount, byteTimestamp2, sigSendAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void sendAmountNullDestinationKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, null, amount, byteTimestamp2, sigSendAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void sendAmountNegativeAmount() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = -30;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void sendAmountNeutralAmount() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 0;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void sendAmountNullTimestamp() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, null, sigSendAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void sendAmountNullSig() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 30;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig, byteTimestamp);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp, null);
	}
	
	@Test(expected = ArgumentsException.class)
	public void checkAccountNullKey() throws Exception {
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC, sig, byteTimestamp);
		hdsLib.checkAccount(null);
	}

	@Test(expected = ArgumentsException.class)
	public void checkAccountEmptyKey() throws Exception {
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC, sig, byteTimestamp);
		hdsLib.checkAccount("");
	}

	@Test(expected = ArgumentsException.class)
	public void checkAccountBlankKey() throws Exception {
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC, sig, byteTimestamp);
		hdsLib.checkAccount("   ");
	}

	@Test(expected = AccountNotFoundException.class)
	public void checkAccountWrongKey() throws Exception {
		String stringPubEC = HDSCrypto.publicKeyToString(pubEC1);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC, sig, byteTimestamp);
		hdsLib.checkAccount(stringPubEC);
	}
	
	@Test(expected = ArgumentsException.class)
	public void receiveAmountNullSourceKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(null, keyhash2, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void receiveAmountEmptySourceKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount("", keyhash2, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void receiveAmountBlankSourceKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount("    ", keyhash2, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void receiveAmountNullDestKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash1, null, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void receiveAmountEmptyDestKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash1, "", id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void receiveAmountBlankDestKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash1, "    ", id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = TransactionNotFoundException.class)
	public void receiveAmountIDnotFound() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		
		int id = 1000;	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash1, keyhash2, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = AccountNotFoundException.class)
	public void receiveAmountSourceAccountNotFound() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(stringPubEC1, keyhash2, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = AccountNotFoundException.class)
	public void receiveAmountDestAccountNotFound() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash1, stringPubEC2, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = TransactionWrongKeyException.class)
	public void receiveAmountWrongSourceAccount() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String stringPubEC3 = HDSCrypto.publicKeyToString(pubEC3);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		String keyhash3 = hashKey(stringPubEC3);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		byte[] sig3 = HDSCrypto.createSignatureEC(byteTimestamp, privEC3);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		hdsLib.register(stringPubEC3, sig3, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash3, keyhash2, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = TransactionWrongKeyException.class)
	public void receiveAmountWrongDestAccount() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String stringPubEC3 = HDSCrypto.publicKeyToString(pubEC3);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		String keyhash3 = hashKey(stringPubEC3);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		byte[] sig3 = HDSCrypto.createSignatureEC(byteTimestamp, privEC3);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		hdsLib.register(stringPubEC3, sig3, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC3);
		hdsLib.receiveAmount(keyhash1, keyhash3, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = TimestampNotFreshException.class)
	public void receiveAmountWrongTimestamp() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.DATE, 2);
		Date timestamp3 = c.getTime();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash1, keyhash2, id, byteTimestamp3, sigReceiveAmount);
	}

	@Test(expected = InvalidSignatureException.class)
	public void receiveAmountWrongSignature() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		String stringPubEC2 = HDSCrypto.publicKeyToString(pubEC2);
		String keyhash1 = hashKey(stringPubEC1);
		String keyhash2 = hashKey(stringPubEC2);
		int amount = 60;
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		byte[] sig2 = HDSCrypto.createSignatureEC(byteTimestamp, privEC2);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC2, sig2, byteTimestamp);
		
		byte[] keyhashs = HDSCrypto.concacBytes(keyhash1.getBytes(), keyhash2.getBytes());
		byte[] hashAmount = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(amount).toByteArray());
		Date timestamp2 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp2 = HDSCrypto.convertDateToByteArray(timestamp2);
		byte[] content = HDSCrypto.concacBytes(hashAmount, byteTimestamp2);
		
		byte[] sigSendAmount = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, byteTimestamp2, sigSendAmount);
		AccountState state = hdsLib.checkAccount(keyhash2);
		
		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.SECOND, 2);
		Date changeTimestamp = c.getTime();
		byte[] changeByteTimestamp = HDSCrypto.convertDateToByteArray(changeTimestamp);
		
		int id = state.getPendingTransactions().get(0).getId();	
		byte[] hashID = HDSCrypto.concacBytes(keyhashs, BigInteger.valueOf(id).toByteArray());
		Date timestamp3 = HDSCrypto.createTimestamp();
		byte[] byteTimestamp3 = HDSCrypto.convertDateToByteArray(timestamp3);
		byte[] content2 = HDSCrypto.concacBytes(hashID, byteTimestamp3);
		
		byte[] sigReceiveAmount = HDSCrypto.createSignatureEC(content2, privEC2);
		hdsLib.receiveAmount(keyhash1, keyhash2, id, changeByteTimestamp, sigReceiveAmount);
	}

	@Test(expected = ArgumentsException.class)
	public void auditNullKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);		
		hdsLib.audit(null);
	}

	@Test(expected = ArgumentsException.class)
	public void auditEmptyKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);		
		hdsLib.audit("");
	}

	@Test(expected = ArgumentsException.class)
	public void auditBlankKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);		
		hdsLib.audit("    ");
	}

	@Test(expected = AccountNotFoundException.class)
	public void auditWrongKey() throws Exception{
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);		
		hdsLib.audit(stringPubEC1);
	}
}