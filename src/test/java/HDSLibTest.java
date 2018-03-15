import domain.Account;
import exceptions.KeyAlreadyRegistered;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.Assert.*;

public class HDSLibTest {
	private HDSLib hdsLib;

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
	public void registerSuccess() throws Exception {
		int key1 = 1;
		int key2 = 2;
		hdsLib.register(key1);
		hdsLib.register(key2);
		Account a1 = hdsLib.getAccount(key1);
		Account a2 = hdsLib.getAccount(key2);
		assertNotNull(a1);
		assertNotNull(a2);
		assertEquals(a1.getKey(), key1);
		assertEquals(a2.getKey(), key2);
		assertEquals(a1.getAmount(), 100);
		assertEquals(a2.getAmount(), 100);
		assertEquals(a1.getTransactions().size(), 0);
		assertEquals(a2.getTransactions().size(), 0);
	}

	@Test(expected = KeyAlreadyRegistered.class)
	public void registerExistingAccount() throws Exception {
		int key = 1;
		hdsLib.register(key);
		hdsLib.register(key);
	}
}