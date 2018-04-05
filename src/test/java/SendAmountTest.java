import domain.Account;
import domain.Transaction;
import exceptions.*;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Calendar;
import java.util.Date;

import static org.junit.Assert.*;

public class SendAmountTest {
	private HDSLib hdsLib;

	private static PublicKey pubKey1;
	private static PrivateKey privKey1;
	private static PublicKey pubKey2;
	private static PrivateKey privKey2;
	private static PublicKey pubKey3;
	private static PrivateKey privKey3;

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

		ec = keyGen.generateKeyPair();
		pubKey3 = ec.getPublic();
		privKey3 = ec.getPrivate();
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

	@Test
	public void SendAmountSuccess() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		TestAux.registerHelper(pubKey3, privKey3, hdsLib);
		String pubHash1 = TestAux.hashKey(pubKey1);
		String pubHash2 = TestAux.hashKey(pubKey2);

		TestAux.sendAmountHelper(pubKey1, pubKey2, 70, privKey1, hdsLib);
		Account sender = hdsLib.getAccount(pubHash1);
		Account receiver = hdsLib.getAccount(pubHash2);
		assertEquals(30, sender.getAmount());
		assertEquals(100, receiver.getAmount());
		assertEquals(1, hdsLib.getAccountTransactions(sender.getKeyHash()).size());
		assertEquals(1, hdsLib.getAccountTransactions(receiver.getKeyHash()).size());

		Transaction transaction = hdsLib.getAccountTransactions(sender.getKeyHash()).get(0);
		assertEquals(70, transaction.getAmount());
		assertEquals(pubHash1, transaction.getFrom().getKeyHash());
		assertEquals(pubHash2, transaction.getTo().getKeyHash());
		assertTrue(transaction.isPending());

		assertNull(transaction.getReceivedTimestamp());
		assertNull(transaction.getReceiverSig());
		Signature s = HDSCrypto.verifySignature(pubKey1);
		s.update(transaction.getFrom().getKeyHash().getBytes());
		s.update(transaction.getTo().getKeyHash().getBytes());
		s.update(BigInteger.valueOf(transaction.getAmount()).toByteArray());
		s.update(HDSCrypto.dateToString(transaction.getSentTimestamp()).getBytes());
		assertTrue(s.verify(transaction.getSenderSig()));

		Transaction newTransaction = TestAux.sendAmountHelper(pubKey2, pubKey3, 100, privKey2, hdsLib);
		assertNotNull(newTransaction);
		assertTrue(newTransaction.getId() > transaction.getId());
	}

	@Test(expected = AccountNotFoundException.class)
	public void sendAmountSourceAccountNotFound() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.sendAmountHelper(pubKey2, pubKey1, 50, privKey2, hdsLib);
	}

	@Test(expected = AccountNotFoundException.class)
	public void sendAmountDestinationAccountNotFound() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.sendAmountHelper(pubKey1, pubKey2, 50, privKey1, hdsLib);
	}

	@Test(expected = SameSourceAndDestAccountException.class)
	public void sendAmountSameAccount() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.sendAmountHelper(pubKey1, pubKey1, 50, privKey1, hdsLib);
	}

	@Test(expected = AccountInsufficientAmountException.class)
	public void sendAmountAccountNotEnough() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		TestAux.sendAmountHelper(pubKey1, pubKey2, 101, privKey1, hdsLib);
	}

	@Test(expected = InvalidAmountException.class)
	public void sendAmountNegativeAmount() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		TestAux.sendAmountHelper(pubKey1, pubKey2, -50, privKey1, hdsLib);
	}

	@Test(expected = InvalidAmountException.class)
	public void sendAmountNeutralAmount() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		TestAux.sendAmountHelper(pubKey1, pubKey2, 0, privKey1, hdsLib);
	}

	@Test(expected = RepeatedTransactionException.class)
	public void sendAmountReplayAttack() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		Date timestamp = new Date();
		Signature s = HDSCrypto.createSignature(privKey1);
		s.update(TestAux.hashKey(pubKey1).getBytes());
		s.update(TestAux.hashKey(pubKey2).getBytes());
		s.update(BigInteger.valueOf(30).toByteArray());
		s.update(HDSCrypto.dateToString(timestamp).getBytes());
		byte[] sig = s.sign();
		TestAux.sendAmountHelper(pubKey1, pubKey2, 30, privKey1, timestamp, sig, hdsLib);
		TestAux.sendAmountHelper(pubKey1, pubKey2, 30, privKey1, timestamp, sig, hdsLib);
	}

	@Test(expected = InvalidSignatureException.class)
	public void sendAmountWrongKey() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		TestAux.sendAmountHelper(pubKey1, pubKey2, 50, privKey2, hdsLib);
	}

	@Test(expected = TimestampNotFreshException.class)
	public void sendAmountWrongTimestamp() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.DATE, 2);
		Date timestamp = c.getTime();

		TestAux.sendAmountHelper(pubKey1, pubKey2, 30, privKey1, timestamp, hdsLib);
	}

	@Test(expected = InvalidSignatureException.class)
	public void sendAmountWrongSig() throws Exception{
		int amount = 50;
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);
		Date timestamp = new Date();
		Signature s = HDSCrypto.createSignature(privKey1);
		s.update(TestAux.hashKey(pubKey1).getBytes());
		s.update(TestAux.hashKey(pubKey2).getBytes());
		s.update(BigInteger.valueOf(amount+1).toByteArray());
		s.update(HDSCrypto.dateToString(timestamp).getBytes());

		TestAux.sendAmountHelper(pubKey1, pubKey2, amount, privKey1, timestamp, s.sign(), hdsLib);
	}
}