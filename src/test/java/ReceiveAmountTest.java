import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import server.HDSCrypto;
import server.HDSLib;
import server.domain.Account;
import server.domain.Transaction;
import server.exceptions.InvalidSignatureException;
import server.exceptions.TimestampNotFreshException;
import server.exceptions.TransactionAlreadyReceivedException;
import server.exceptions.TransactionNotFoundException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.Calendar;
import java.util.Date;

import static org.junit.Assert.*;

public class ReceiveAmountTest {
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
	public void receiveSuccess() throws Exception {
		TestAux.registerHelper(pubKey1, privKey1, hdsLib).getKeyHash();
		String a2Hash = TestAux.registerHelper(pubKey2, privKey2, hdsLib).getKeyHash();

		Transaction sentTransaction = TestAux.sendAmountHelper(pubKey1, pubKey2, 50, "000000", privKey1, hdsLib);
		TestAux.receiveAmountHelper(sentTransaction.getId(), privKey2, sentTransaction.getTransactionHash(), hdsLib);
		Transaction doneTransaction = hdsLib.getTransaction(sentTransaction.getId());
		assertNotNull(doneTransaction.getSenderSig());
		assertNotNull(doneTransaction.getSig());
		Signature s = HDSCrypto.verifySignature(pubKey2);
		s.update(doneTransaction.getId().getBytes());
		s.update(doneTransaction.getTimestamp().getBytes());
		assertTrue(s.verify(doneTransaction.getSig()));

		Account a2 = hdsLib.getAccount(a2Hash);
		assertEquals(150, a2.getAmount());
		assertEquals(1, hdsLib.getAccountTransactions(a2.getKeyHash()).size());
		assertFalse(hdsLib.getAccountTransactions(a2.getKeyHash()).get(0).isPending());
	}

	@Test(expected = TransactionNotFoundException.class)
	public void receiveAmountIdNotFound() throws Exception{
		TestAux.receiveAmountHelper("69-asd", privKey1, "000000", hdsLib);
	}

	@Test(expected = TransactionAlreadyReceivedException.class)
	public void receiveAmountAlreadyReceived() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib).getKeyHash();
		TestAux.registerHelper(pubKey2, privKey2, hdsLib).getKeyHash();
		Transaction sentTransaction = TestAux.sendAmountHelper(pubKey1, pubKey2, 50, "000000", privKey1, hdsLib);

		TestAux.receiveAmountHelper(sentTransaction.getId(), privKey2, sentTransaction.getTransactionHash(),hdsLib);
		TestAux.receiveAmountHelper(sentTransaction.getId(), privKey2, sentTransaction.getTransactionHash(), hdsLib);
	}

	@Test(expected = InvalidSignatureException.class)
	public void receiveAmountWrongKey() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib).getKeyHash();
		TestAux.registerHelper(pubKey2, privKey2, hdsLib).getKeyHash();
		Transaction sentTransaction = TestAux.sendAmountHelper(pubKey1, pubKey2, 50, "000000", privKey1, hdsLib);

		TestAux.receiveAmountHelper(sentTransaction.getId(), privKey1,sentTransaction.getTransactionHash(), hdsLib);
	}

	@Test(expected = TimestampNotFreshException.class)
	public void receiveAmountWrongTimestamp() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib).getKeyHash();
		TestAux.registerHelper(pubKey2, privKey2, hdsLib).getKeyHash();
		Transaction sentTransaction = TestAux.sendAmountHelper(pubKey1, pubKey2, 50, "000000",privKey1, hdsLib);

		Calendar c = Calendar.getInstance();
		c.setTime(new Date());
		c.add(Calendar.DATE, 2);
		Date timestamp = c.getTime();
		TestAux.receiveAmountHelper(sentTransaction.getId(), privKey1, sentTransaction.getTransactionHash(),HDSCrypto.dateToString(timestamp), hdsLib);
	}

	@Test(expected = InvalidSignatureException.class)
	public void receiveAmountWrongSignature() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib).getKeyHash();
		TestAux.registerHelper(pubKey2, privKey2, hdsLib).getKeyHash();
		Transaction sentTransaction = TestAux.sendAmountHelper(pubKey1, pubKey2, 50, "000000",privKey1, hdsLib);

		Date timestamp = new Date();
		Signature s = HDSCrypto.createSignature(privKey1);
		s.update((sentTransaction.getId()+"a").getBytes());
		s.update(HDSCrypto.dateToString(timestamp).getBytes());
		TestAux.receiveAmountHelper(sentTransaction.getId(), privKey1, sentTransaction.getTransactionHash(),HDSCrypto.dateToString(timestamp), s.sign(), hdsLib);
	}
}