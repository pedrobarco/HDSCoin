import domain.Account;
import domain.Transaction;
import exceptions.InvalidSignatureException;
import exceptions.NullArgumentException;
import exceptions.TimestampNotFreshException;
import exceptions.TransactionNotFoundException;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

public class ReceiveAmountTest {
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
	public void receiveSuccess() throws Exception {
		String a1Hash = TestAux.registerHelper(pubKey1, privKey1, hdsLib).getKeyHash();
		String a2Hash = TestAux.registerHelper(pubKey2, privKey2, hdsLib).getKeyHash();

		Transaction sentTransaction = TestAux.sendAmountHelper(pubKey1, pubKey2, 50, privKey1, hdsLib);
		TestAux.receiveAmountHelper(sentTransaction.getId(), privKey2, hdsLib);

		Account a2 = hdsLib.getAccount(a2Hash);
		assertEquals(150, a2.getAmount());
		assertEquals(1, hdsLib.getAccountTransactions(a2.getKeyHash()).size());
		assertFalse(hdsLib.getAccountTransactions(a2.getKeyHash()).get(0).isPending());
	}

	@Test(expected = TransactionNotFoundException.class)
	public void receiveAmountIdNotFound() throws Exception{
		TestAux.receiveAmountHelper(691, privKey1, hdsLib);
	}

	@Test(expected = InvalidSignatureException.class)
	public void receiveAmountWrongKey() throws Exception{
		TestAux.registerHelper(pubKey1, privKey1, hdsLib).getKeyHash();
		TestAux.registerHelper(pubKey2, privKey2, hdsLib).getKeyHash();

		Transaction sentTransaction = TestAux.sendAmountHelper(pubKey1, pubKey2, 50, privKey1, hdsLib);
		TestAux.receiveAmountHelper(sentTransaction.getId(), privKey1, hdsLib);
	}

	@Test(expected = TimestampNotFreshException.class)
	public void receiveAmountWrongTimestamp() throws Exception{
		// TODO
		throw new NotImplementedException();
	}

	@Test(expected = InvalidSignatureException.class)
	public void receiveAmountWrongSignature() throws Exception{
		// TODO
		throw new NotImplementedException();
	}

	@Test(expected = NullArgumentException.class)
	public void receiveAmountNullSourceKey() throws Exception{
		// TODO
		throw new NotImplementedException();
	}

	@Test(expected = NullArgumentException.class)
	public void receiveAmountNullDestKey() throws Exception{
		// TODO
		throw new NotImplementedException();
	}
}