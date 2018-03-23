import domain.Account;
import domain.AccountState;
import exceptions.KeyAlreadyRegistered;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;
import java.util.Date;

import static java.util.Base64.getEncoder;
import static org.junit.Assert.*;

public class HDSLibTest {
	private HDSLib hdsLib;

	private static PublicKey pubEC1;
	private static PrivateKey privEC1;
	private static PublicKey pubEC2;
	private static PrivateKey privEC2;
	
	private static String pubkey2;
	private static String privkey2;
	private static String pubkey3;
	private static String privkey3;
	private static String pubkey4;
	private static String privkey4;

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
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		keyGen.initialize(224, random);
		
		KeyPair ec = keyGen.generateKeyPair();
		pubEC1 = ec.getPublic();
		privEC1 = ec.getPrivate();
		
		ec = keyGen.generateKeyPair();
		pubEC2 = ec.getPublic();
		privEC2 = ec.getPrivate();
		
		
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
			digester = MessageDigest.getInstance("SHA-256");
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
		hdsLib.register(stringPubEC2, sig2, byteTimestamp); //TODO: questao: o que era suposto caso o timestamp fosse igual?
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

	@Test(expected = KeyAlreadyRegistered.class)
	public void registerExistingAccount() throws Exception {
		String stringPubEC1 = HDSCrypto.publicKeyToString(pubEC1);
		Date timestamp = HDSCrypto.createTimestamp();
		byte[] byteTimestamp = HDSCrypto.convertDateToByteArray(timestamp);
		byte[] sig1 = HDSCrypto.createSignatureEC(byteTimestamp, privEC1);
		//SealedObject timestamp1 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey1), timestamp);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
		hdsLib.register(stringPubEC1, sig1, byteTimestamp);
	}
	
	//falta testes para sig errada e timestamp >= 60

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
		
		byte[] sigSendAmount1 = HDSCrypto.createSignatureEC(content, privEC1);
		hdsLib.sendAmount(keyhash1, keyhash2, amount, newByteTimestamp, sigSendAmount1);
		AccountState state = hdsLib.checkAccount(keyhash1);
		assertNotNull(state);
		assertEquals(state.getAmount(), 70);
		assertEquals(state.getPendingTransactions().size(), 0);
		
		state = hdsLib.checkAccount(keyhash2);
		assertNotNull(state);
		assertEquals(state.getAmount(), 100);
		assertEquals(state.getPendingTransactions().size(), 1);
	}
}