import server.HDSCrypto;
import server.HDSLib;
import server.domain.Account;
import server.domain.Transaction;

import java.math.BigInteger;
import java.security.*;
import java.util.Base64;
import java.util.Date;


public class TestAux {
	public static String hashKey(Key key) {
		MessageDigest digester = null;
		try {
			digester = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		digester.update(key.getEncoded());
		return Base64.getEncoder().encodeToString(digester.digest());
	}

	public static Account registerHelper(PublicKey pubkey, PrivateKey privkey, String timestamp, byte[] sig, HDSLib hdsLib) throws Exception {
		return hdsLib.register(pubkey, timestamp, sig);
	}

	public static Account registerHelper(PublicKey pubkey, PrivateKey privkey, String timestamp, HDSLib hdsLib) throws Exception {
		Signature s = HDSCrypto.createSignature(privkey);
		s.update(timestamp.getBytes());
		return registerHelper(pubkey, privkey, timestamp, s.sign(), hdsLib);
	}

	public static Account registerHelper(PublicKey pubkey, PrivateKey privkey, HDSLib hdsLib) throws Exception {
		return registerHelper(pubkey, privkey, HDSCrypto.dateToString(new Date()), hdsLib);
	}

	public static Transaction sendAmountHelper(PublicKey srckey, PublicKey destkey, int amount, PrivateKey privkey, String previousTransaction, String timestamp, byte[] sig, HDSLib hdsLib) throws Exception {
		String srckeyHash = hashKey(srckey);
		String destkeyHash = hashKey(destkey);
		return hdsLib.sendAmount(srckeyHash, destkeyHash, amount, previousTransaction, timestamp, sig);
	}

	public static Transaction sendAmountHelper(PublicKey srckey, PublicKey destkey, int amount, String previousTransaction, PrivateKey privkey, String timestamp, HDSLib hdsLib) throws Exception {
		String srckeyHash = hashKey(srckey);
		String destkeyHash = hashKey(destkey);
		Signature s = HDSCrypto.createSignature(privkey);
		s.update(srckeyHash.getBytes());
		s.update(destkeyHash.getBytes());
		s.update(BigInteger.valueOf(amount).toByteArray());
		s.update(previousTransaction.getBytes());
		s.update(timestamp.getBytes());
		return sendAmountHelper(srckey, destkey, amount, privkey, previousTransaction, timestamp, s.sign(), hdsLib);
	}

	public static Transaction sendAmountHelper(PublicKey srckey, PublicKey destkey, int amount, String previousTransaction, PrivateKey privkey, HDSLib hdsLib) throws Exception {
		return sendAmountHelper(srckey, destkey, amount, previousTransaction, privkey, HDSCrypto.dateToString(new Date()), hdsLib);
	}

	public static void receiveAmountHelper(String  id, PrivateKey privkey, String previousTransaction, String timestamp, byte[] sig, HDSLib hdsLib) throws Exception{
		hdsLib.receiveAmount(id, null, previousTransaction, timestamp, sig);
	}

	public static void receiveAmountHelper(String id, PrivateKey privkey, String previousTransaction, String timestamp, HDSLib hdsLib) throws Exception{
		Signature s = HDSCrypto.createSignature(privkey);
		s.update(id.getBytes());
		s.update(previousTransaction.getBytes());
		s.update(timestamp.getBytes());
		receiveAmountHelper(id, privkey, previousTransaction, timestamp, s.sign(), hdsLib);
	}

	public static void receiveAmountHelper(String id, PrivateKey privkey, String previousTransaction, HDSLib hdsLib) throws Exception{
		receiveAmountHelper(id, privkey, previousTransaction, HDSCrypto.dateToString(new Date()), hdsLib);
	}
}
