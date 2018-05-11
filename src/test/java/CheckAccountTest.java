import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import server.HDSLib;
import server.domain.Account;
import server.domain.AccountState;
import server.domain.Transaction;
import server.exceptions.AccountNotFoundException;
import server.exceptions.NullArgumentException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class CheckAccountTest {
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
	public void checkAccountSuccess() throws Exception {
		Account a1 = TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		Account a2 = TestAux.registerHelper(pubKey2, privKey2, hdsLib);

		AccountState s1 = hdsLib.checkAccount(a1.getKeyHash());
		assertNotNull(s1);
		assertEquals(a1.getKeyHash(), s1.getKeyHash());
		assertEquals(100, s1.getAmount());
		assertEquals(0, s1.getPendingTransactions().size());

		Transaction t = TestAux.sendAmountHelper(pubKey2, pubKey1, 30, "000000",privKey2, hdsLib);
		AccountState receiver = hdsLib.checkAccount(a1.getKeyHash());
		assertNotNull(receiver);
		assertEquals(a1.getKeyHash(), receiver.getKeyHash());
		assertEquals(100, receiver.getAmount());
		assertEquals(1, receiver.getPendingTransactions().size());
		AccountState sender = hdsLib.checkAccount(a2.getKeyHash());
		assertNotNull(sender);
		assertEquals(a2.getKeyHash(), sender.getKeyHash());
		assertEquals(70, sender.getAmount());
		assertEquals(0, sender.getPendingTransactions().size());

		TestAux.receiveAmountHelper(t.getId(),t.getSig(), privKey1, t.getTransactionHash(),hdsLib);
		receiver = hdsLib.checkAccount(a1.getKeyHash());
		assertNotNull(receiver);
		assertEquals(a1.getKeyHash(), receiver.getKeyHash());
		assertEquals(130, receiver.getAmount());
		assertEquals(0, receiver.getPendingTransactions().size());
		sender = hdsLib.checkAccount(a2.getKeyHash());
		assertNotNull(sender);
		assertEquals(a2.getKeyHash(), sender.getKeyHash());
		assertEquals(70, sender.getAmount());
		assertEquals(0, sender.getPendingTransactions().size());
	}

	@Test(expected = AccountNotFoundException.class)
	public void checkAccountNonExistingKey() throws Exception {
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.checkAccount(TestAux.hashKey(pubKey2));
	}

	@Test(expected = AccountNotFoundException.class)
	public void checkAccountDeformedKey() throws Exception {
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.checkAccount("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!#$%&/()=?\"");
	}

	@Test(expected = NullArgumentException.class)
	public void checkAccountNullKey() throws Exception {
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.checkAccount(null);
	}

	@Test(expected = NullArgumentException.class)
	public void checkAccountEmptyKey() throws Exception {
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.checkAccount("");
	}

	@Test(expected = NullArgumentException.class)
	public void checkAccountBlankKey() throws Exception {
		TestAux.registerHelper(pubKey1, privKey1, hdsLib);
		hdsLib.checkAccount(" ");
	}
}