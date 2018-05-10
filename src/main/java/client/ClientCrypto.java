package client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mashape.unirest.http.JsonNode;
import org.json.JSONException;
import org.json.JSONObject;
import sun.security.x509.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static client.Client.debug;

@SuppressWarnings("Duplicates")
public class ClientCrypto {
    public static X509Certificate generateCertificate(String dn, KeyPair keyPair, int validity, String sigAlgName) throws GeneralSecurityException, IOException {
        PrivateKey privateKey = keyPair.getPrivate();

        X509CertInfo info = new X509CertInfo();

        Date from = new Date();
        Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);
        AlgorithmId sigAlgId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);

        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
        info.set(X509CertInfo.SUBJECT, owner);
        info.set(X509CertInfo.ISSUER, owner);
        info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(sigAlgId));

        X509CertImpl certificate = new X509CertImpl(info);
        certificate.sign(privateKey, sigAlgName);

        sigAlgId = (AlgorithmId) certificate.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, sigAlgId);
        certificate = new X509CertImpl(info);
        certificate.sign(privateKey, sigAlgName);

        return certificate;
    }

    public static Signature createSignature(PrivateKey priv) throws InvalidKeyException {
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

    public static boolean checkServerSignature(JsonNode response, String timestamp, PublicKey serverKey){
        byte[] serverSig = null;
        try {
            serverSig = Base64.getDecoder().decode(response.getObject().getString("serverSig"));
        } catch (JSONException e) {
            if (debug == Client.debugMode.VERBOSE) {
                System.out.println("[DEBUG] Couldn't find the serverSig");
            }
            return false;
        }

        try {
            Signature serverSigVerify = verifySignature(serverKey);
            serverSigVerify.update(timestamp.getBytes());
            if (!serverSigVerify.verify(serverSig)){
                if (debug == Client.debugMode.VERBOSE) {
                    System.out.println("[DEBUG] Failed to verify the serverSig");
                }
                return false;
            }
        } catch (InvalidKeyException | SignatureException e) {
            if (debug == Client.debugMode.VERBOSE) {
                System.out.println("[DEBUG] Exception while verifying serverSig:");
                System.out.println("[DEBUG] " + e.getMessage());
            }
            return false;
        }
        return true;
    }

    public static String urlEncode(String url) {
        return url.replace("+",".").replace("/","_").replace("=","-");
    }

    // TODO: Consider renaming class to ClientAux
    public static String prettyPrintJsonString(JsonNode jsonNode) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            Object json = mapper.readValue(jsonNode.toString(), Object.class);
            return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
        } catch (Exception e) {
            System.out.println("AHHHHHHHHHHHHHHHHHHHHHHHHHHHHH");
            e.printStackTrace();
            return "Sorry, pretty print didn't work";
        }
    }

    public static String prettyPrintPendingTransaction(JSONObject transaction) {
        String id = transaction.getString("id");
        String amount = Integer.toString(transaction.getInt("amount"));
        String from = transaction.getJSONObject("from").getString("keyHash");
        String signature = transaction.getString("sig");
        return "  Transaction " + id + ": " + amount + " coins [FROM: " + from + " | SIGNATURE: " + signature + "]";
    }

    public static String prettyPrintTransaction(JSONObject transaction) {
        String id = transaction.getString("id");
        String amount = Integer.toString(transaction.getInt("amount"));
        String from = transaction.getJSONObject("from").getString("keyHash");
        String to = transaction.getJSONObject("to").getString("keyHash");
        boolean pending = transaction.getBoolean("pending");
        return "Transaction " + id + "\nAmount: " + amount + "\nFrom: " + from + "\nTo: " + to + "\nPending: " + pending;
    }
}
