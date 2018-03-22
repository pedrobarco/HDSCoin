import javax.crypto.Cipher;
import javax.crypto.SealedObject;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class HDSCrypto {
	
	private static byte[] digestMessage(String message) throws NoSuchAlgorithmException{
		MessageDigest md = MessageDigest.getInstance("SHA-384");//384 para simetrica e 512 para assimetrica?
		return md.digest(message.getBytes());		
	}
	
	private static KeyPair generateKeypairEC() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException{
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "SunEC");
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		keyGen.initialize(224, random); //160 eq to 1024 rsa; 224 eq to 2048 rsa
		return keyGen.generateKeyPair();
	}
	
	private static byte[] createSignatureEC(byte[] data, PrivateKey priv) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException{
		Signature s = Signature.getInstance("SHA1withECDSA");
		s.initSign(priv);             // Initialize it; can throw InvalidKeyException
		s.update(data);              // Data to sign; can throw SignatureException
		byte[] signature = s.sign(); // Compute signature
		return signature;
	}
	
	private static boolean verifySignature(byte[] data, PublicKey pub, byte[] sig) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException{
		Signature s = Signature.getInstance("SHA1withECDSA");
		s.initVerify(pub);                            // Setup for verification
		s.update(data);                                     // Specify signed data
		return s.verify(sig);  
	}
	
	
	public static String publicKeyToString(PublicKey key){
		return new String(Base64.getEncoder().encode(key.getEncoded()));
	}

	public static PublicKey stringToPublicKey(String key) throws InvalidKeySpecException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String privateKeyToString(PrivateKey key){
		return new String(Base64.getEncoder().encode(key.getEncoded()));
	}

	public static PrivateKey stringToPrivateKey(String key) throws InvalidKeySpecException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(key));
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			return keyFactory.generatePrivate(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static SealedObject encrypt(Key key, String message) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);

		return new SealedObject(message, cipher);
	}

	public static String decrypt(Key key, SealedObject encrypted) throws Exception {
		return (String) encrypted.getObject(key);
	}

	public static String getCurrentTimestamp() {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss");
		return dateFormat.format(new Date());
	}

	public static Date timestampToDate(String timestamp) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss");
		try {
			return dateFormat.parse(timestamp);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return null;
	}
}
