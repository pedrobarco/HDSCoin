import domain.Account;
import domain.Transaction;

import java.math.BigInteger;
import java.security.*;
import java.util.Base64;
import java.util.Date;


public class TestAux {
	public static String hashKey(Key key) {
		MessageDigest digester = null;
		try {
			digester = MessageDigest.getInstance("SHA-256"); //TODO
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		digester.update(key.getEncoded());
		return Base64.getEncoder().encodeToString(digester.digest());
	}

	public static Account registerHelper(PublicKey pubkey, PrivateKey privkey, Date timestamp, byte[] sig, HDSLib hdsLib) throws Exception {
		return hdsLib.register(pubkey, timestamp, sig);
	}

	public static Account registerHelper(PublicKey pubkey, PrivateKey privkey, Date timestamp, HDSLib hdsLib) throws Exception {
		Signature s = HDSCrypto.createSignature(privkey);
		s.update(HDSCrypto.dateToString(timestamp).getBytes());
		return registerHelper(pubkey, privkey, timestamp, s.sign(), hdsLib);
	}

	public static Account registerHelper(PublicKey pubkey, PrivateKey privkey, HDSLib hdsLib) throws Exception {
		return registerHelper(pubkey, privkey, new Date(), hdsLib);
	}


	public static Transaction sendAmountHelper(PublicKey srckey, PublicKey destkey, int amount, PrivateKey privkey, HDSLib hdsLib) throws Exception {
		// TODO: Divide me like registerHelper
		String srckeyHash = hashKey(srckey);
		String destkeyHash = hashKey(destkey);
		Date timestamp = new Date();
		Signature s = HDSCrypto.createSignature(privkey);
		s.update(srckeyHash.getBytes());
		s.update(destkeyHash.getBytes());
		s.update(BigInteger.valueOf(amount).toByteArray());
		s.update(HDSCrypto.dateToString(timestamp).getBytes());
		return hdsLib.sendAmount(srckeyHash, destkeyHash, amount, timestamp, s.sign());
	}


	public static void receiveAmountHelper(int id, PrivateKey privkey, HDSLib hdsLib) throws Exception{
		Date timestamp = new Date();
		Signature s = HDSCrypto.createSignature(privkey);
		s.update(BigInteger.valueOf(id).toByteArray());
		s.update(HDSCrypto.dateToString(timestamp).getBytes());
		hdsLib.receiveAmount(id, timestamp, s.sign());
	}
}
