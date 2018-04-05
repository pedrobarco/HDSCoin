import domain.Transaction;
import exceptions.AccountNotFoundException;
import exceptions.NullArgumentException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class AuditTest {
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
		Files.deleteIfExists(Paths.get("./db/test.mv.db"));
		Files.deleteIfExists(Paths.get("./db/test.trace.db"));
	}

	@Test
	public void auditSuccess() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		TestAux.registerHelper(pubKey2, privKey2, hdsLib);

		List<Transaction> transactionList = hdsLib.audit(TestAux.hashKey(pubKey1));
		assertNotNull(transactionList);
		assertEquals(0, transactionList.size());

		Transaction t = TestAux.sendAmountHelper(pubKey1, pubKey2, 30, privKey1, hdsLib);
		List<Transaction> senderList = hdsLib.audit(TestAux.hashKey(pubKey1));
		List<Transaction> receiverList = hdsLib.audit(TestAux.hashKey(pubKey1));
		assertNotNull(senderList);
		assertEquals(1, senderList.size());
		assertEquals(t, senderList.get(0));
		assertNotNull(receiverList);
		assertEquals(1, receiverList.size());
		assertEquals(t, receiverList.get(0));

		TestAux.receiveAmountHelper(t.getId(), privKey2, hdsLib);
		t = hdsLib.getTransaction(t.getId());
		senderList = hdsLib.audit(TestAux.hashKey(pubKey1));
		receiverList = hdsLib.audit(TestAux.hashKey(pubKey1));
		assertNotNull(senderList);
		assertEquals(1, senderList.size());
		assertEquals(t, senderList.get(0));
		assertNotNull(receiverList);
		assertEquals(1, receiverList.size());
		assertEquals(t, receiverList.get(0));
	}

	@Test(expected = AccountNotFoundException.class)
	public void auditNonExistingKey() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.audit(TestAux.hashKey(pubKey2));
	}

	@Test(expected = AccountNotFoundException.class)
	public void auditDeformedKey() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.audit("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%&/()=?\"");
	}

	@Test(expected = NullArgumentException.class)
	public void auditNullKey() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.audit(null);
	}

	@Test(expected = NullArgumentException.class)
	public void auditEmptyKey() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.audit("");
	}

	@Test(expected = NullArgumentException.class)
	public void auditBlankKey() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.audit(" ");
	}
}