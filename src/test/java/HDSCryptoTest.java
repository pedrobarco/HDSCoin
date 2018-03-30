import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SealedObject;
import java.security.*;
import java.util.Base64;

import static org.junit.Assert.*;

public class HDSCryptoTest {
	private static String pubkey1;
	private static String privkey1;
	//private static String pubkey2;
	//private static String privkey2;

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
		//pair = keyGen.generateKeyPair();
		//pubkey2 = new String(Base64.getEncoder().encode(pair.getPublic().getEncoded()));
		//privkey2 = new String(Base64.getEncoder().encode(pair.getPrivate().getEncoded()));
	}

	@Before
	public void setUp() throws Exception {

	}

	@After
	public void tearDown() throws Exception {

	}

	@Test
	public void keyConversionTest() throws Exception {
		PublicKey pubkey = HDSCrypto.stringToPublicKey(pubkey1);
		assertNotNull(pubkey);
		String convertedPubKey = HDSCrypto.publicKeyToString(pubkey);
		assertNotNull(convertedPubKey);
		assertEquals(pubkey1, convertedPubKey);

		PrivateKey privkey = HDSCrypto.stringToPrivateKey(privkey1);
		assertNotNull(privkey);
		String convertedPrivKey = HDSCrypto.privateKeyToString(privkey);
		assertNotNull(convertedPrivKey);
		assertEquals(privkey1, convertedPrivKey);
	}

	@Test
	public void encryptionTest() throws Exception {
		String original = "Hello World";
		SealedObject encrypted = HDSCrypto.encrypt(HDSCrypto.stringToPrivateKey(privkey1), original);
		assertNotNull(encrypted);
		String decrypted = HDSCrypto.decrypt(HDSCrypto.stringToPublicKey(pubkey1), encrypted);
		assertNotNull(decrypted);
		assertEquals(original, decrypted);
	}

}