import domain.Account;
import domain.AccountState;
import exceptions.KeyAlreadyRegistered;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Base64;

import static java.util.Base64.getEncoder;
import static org.junit.Assert.*;

public class HDSLibTest {
	private HDSLib hdsLib;

	private static String pubkey1;
	private static String privkey1;
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

		// Generate 4 key pairs for testing
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
		privkey4 = new String(Base64.getEncoder().encode(pair.getPrivate().getEncoded()));
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
		String keyhash1 = hashKey(pubkey1);
		String keyhash2 = hashKey(pubkey2);
		String timestamp = HDSCrypto.getCurrentTimestamp();
		SealedObject timestamp1 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey1), timestamp);
		SealedObject timestamp2 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey2), timestamp);
		hdsLib.register(pubkey1, timestamp1);
		hdsLib.register(pubkey2, timestamp2);
		Account a1 = hdsLib.getAccount(keyhash1);
		Account a2 = hdsLib.getAccount(keyhash2);
		assertNotNull(a1);
		assertNotNull(a2);
		assertEquals(a1.getKey(), pubkey1);
		assertEquals(a2.getKey(), pubkey2);
		assertEquals(a1.getKeyHash(), keyhash1);
		assertEquals(a2.getKeyHash(), keyhash2);
		assertEquals(a1.getAmount(), 100);
		assertEquals(a2.getAmount(), 100);
		assertEquals(a1.getTransactions().size(), 0);
		assertEquals(a2.getTransactions().size(), 0);
	}

	@Test(expected = KeyAlreadyRegistered.class)
	public void registerExistingAccount() throws Exception {
		String timestamp = HDSCrypto.getCurrentTimestamp();
		SealedObject timestamp1 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey1), timestamp);
		hdsLib.register(pubkey1, timestamp1);
		hdsLib.register(pubkey1, timestamp1);
	}

	@Test
	public void checkAccountSuccess() throws Exception {
		String keyhash1 = hashKey(pubkey1);
		String keyhash2 = hashKey(pubkey2);
		String timestamp = HDSCrypto.getCurrentTimestamp();
		SealedObject timestamp1 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey1), timestamp);
		SealedObject timestamp2 = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey2), timestamp);
		hdsLib.register(pubkey1, timestamp1);
		hdsLib.register(pubkey2, timestamp2);;
		hdsLib.sendAmount(keyhash1, keyhash2, 30);
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