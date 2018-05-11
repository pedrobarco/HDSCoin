import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import server.HDSCrypto;
import server.HDSLib;
import server.domain.Account;
import server.exceptions.InvalidSignatureException;
import server.exceptions.KeyAlreadyRegistered;
import server.exceptions.NullArgumentException;
import server.exceptions.TimestampNotFreshException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Calendar;
import java.util.Date;

import static org.junit.Assert.*;

public class RegisterTest {
	private HDSLib hdsLib;

	private static PublicKey pubKey1;
	private static PrivateKey privKey1;
	private static PublicKey pubKey2;
	private static PrivateKey privKey2;

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
		pubKey1 = ec.getPublic();
		privKey1 = ec.getPrivate();

		ec = keyGen.generateKeyPair();
		pubKey2 = ec.getPublic();
		privKey2 = ec.getPrivate();
	}

	@Before
	public void setUp() throws Exception {
		hdsLib = HDSLib.getTestingInstance();
	}

	@After
	public void tearDown() throws Exception {
		HDSLib.forceReset();
		Files.deleteIfExists(Paths.get("./db/test0.mv.db"));
		Files.deleteIfExists(Paths.get("./db/test0.trace.db"));
	}

	@Test
	public void registerSuccess() throws Exception {
		String keyHash1 = TestAux.hashKey(pubKey1);
		String keyHash2 = TestAux.hashKey(pubKey2);

		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		Account a1 = hdsLib.getAccount(keyHash1);
		Account a2 = hdsLib.getAccount(keyHash2);
		assertNotNull(a1);
		assertNotNull(a2);

		assertNotNull(a1.getKey());
		assertNotNull(a2.getKey());
		assertEquals(a1.getKey(), pubKey1);
		assertEquals(a2.getKey(), pubKey2);
		assertNotEquals(pubKey1, pubKey2);

		assertEquals(a1.getKeyHash(), keyHash1);
		assertEquals(a2.getKeyHash(), keyHash2);
		assertNotEquals(keyHash1, keyHash2);

		assertEquals(a1.getAmount(), 100);
		assertEquals(a2.getAmount(), 100);

		assertEquals(hdsLib.getAccountTransactions(a1.getKeyHash()).size(), 0);
		assertEquals(hdsLib.getAccountTransactions(a2.getKeyHash()).size(), 0);
	}

	@Test(expected = KeyAlreadyRegistered.class)
	public void registerExistingAccount() throws Exception {
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
	}

	@Test(expected = InvalidSignatureException.class)
	public void registerWrongKey() throws Exception {
		TestAux.registerHelper(pubKey1, privKey2, hdsLib);
	}

	@Test(expected = InvalidSignatureException.class)
	public void registerWrongSignature() throws Exception{
		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.SECOND, 2);
		Date changeTimestamp = c.getTime();
		Date timestamp = new Date();

		Signature s = HDSCrypto.createSignature(privKey1);
		s.update(HDSCrypto.dateToString(timestamp).getBytes());
		TestAux.registerHelper(pubKey1, privKey1, HDSCrypto.dateToString(changeTimestamp), s.sign(), hdsLib);
	}

	@Test(expected = TimestampNotFreshException.class)
	public void registerWrongTimestamp() throws Exception{
		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.DATE, 2);
		Date timestamp = c.getTime();

		TestAux.registerHelper(pubKey1,privKey1,HDSCrypto.dateToString(timestamp),hdsLib);
	}

	@Test(expected = NullArgumentException.class)
	public void registerNullKey() throws Exception {
		TestAux.registerHelper(null, privKey1, hdsLib);
	}

	@Test(expected = NullArgumentException.class)
	public void registerNullTimestamp() throws Exception {
		Signature s = HDSCrypto.createSignature(privKey1);
		s.update(HDSCrypto.dateToString(new Date()).getBytes());
		TestAux.registerHelper(pubKey1, privKey1, null, s.sign(), hdsLib);
	}

	@Test(expected = NullArgumentException.class)
	public void registerNullSig() throws Exception {
		TestAux.registerHelper(pubKey1, privKey1, HDSCrypto.dateToString(new Date()), null, hdsLib);
	}
}