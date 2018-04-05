import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

public class HDSCrypto {
	
	public static SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss");
	
	public static boolean validateTimestamp(Date receivedDate, Date timeSent) {
		//String time = dateFormat.format(timeSent);
		//Date sentDate = dateFormat.parse(time);
		long diff = receivedDate.getTime() - timeSent.getTime();
		long diffSeconds = diff / 1000;
		if( diffSeconds < -60 || diffSeconds > 60 ){
			return false;
		}
		return true;
	}
	
	public static Signature createSignature(PrivateKey priv) throws InvalidKeyException{
		Signature s = null;
		try {
			s = Signature.getInstance("SHA256withECDSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		s.initSign(priv);
		return s;
	}
	
	public static Signature verifySignature(PublicKey pub) throws InvalidKeyException {
		Signature s = null;
		try {
			s = Signature.getInstance("SHA256withECDSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		s.initVerify(pub);
		return s;
	}
	
	
	public static String publicKeyToString(PublicKey key){
		return new String(Base64.getEncoder().encode(key.getEncoded()));
	}

	public static PublicKey stringToPublicKey(String key) {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(key));
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("EC", "SunEC");
			return keyFactory.generatePublic(keySpec);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
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

	public static Date stringToDate(String timestamp) {
		try {
			return dateFormat.parse(timestamp);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return null;
	}

	public static String dateToString(Date timestamp) {
		return dateFormat.format(timestamp);
	}
}
