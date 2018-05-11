package client.commands;

import client.Client;
import client.domain.Server;
import client.domain.Transaction;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.apache.http.conn.HttpHostConnectException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.text.SimpleDateFormat;
import java.util.*;

import static client.Client.debug;
import static client.ClientCrypto.*;

@SuppressWarnings("Duplicates")
public class Audit implements Runnable {
    private Server server;
    private String publicKeyHash;
    private String timestamp;
    private PublicKey publicKey;
    private int opid;

    public Audit(Server server, String publicKeyHash, String timestamp, PublicKey publicKey, int opid){
        this.server = server;
        this.publicKeyHash = publicKeyHash;
        this.timestamp = timestamp;
        this.publicKey = publicKey;
        this.opid = opid;
    }

    @Override
    public void run() {
        String address = server.getAddress() + "/hds/"+urlEncode(publicKeyHash)+"/audit";

        try {
            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("timestamp", timestamp)
                    .asJson();

            if (debug == Client.debugMode.VERBOSE) {
                System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
            }

            if (!checkServerSignature(jsonResponse.getBody(), timestamp, server.getPublicKey())) {
                Client.callbackError(server, "Could not verify the server's signature", opid);
                return;
            } else if (jsonResponse.getStatus() == 400) {
                Client.callbackError(server, jsonResponse.getBody().getObject().getString("message"), opid);
                return;
            } else if (jsonResponse.getStatus() == 200) {
                JSONArray array = jsonResponse.getBody().getObject().getJSONArray("transactions");
                System.out.println("[DEBUG] verifying " + array.length() + " transactions from the audit");
                LinkedList<Transaction> transactionList = new LinkedList<>();
                for (int i = array.length() - 1; i >= 0; i--) {
                    JSONObject transaction = array.getJSONObject(i);
                    Transaction t = new Transaction(transaction.getString("id"),
                            transaction.getJSONObject("from").getString("keyHash"),
                            transaction.getJSONObject("to").getString("keyHash"),
                            transaction.getInt("amount"),
                            transaction.getString("sig"),
                            transaction.getString("transactionHash"));
                    System.out.println("[DEBUG] verifying transaction with id " + transaction.getString("id"));
                    Signature s = null;
                    if (transaction.getBoolean("receiving")) {
                        // Transaction comes from a receive operation
                        try {
                            s = verifySignature(publicKey);
                            s.update(BigInteger.valueOf(transaction.getInt("senderId")).toByteArray());
                            s.update(Base64.getDecoder().decode(transaction.getString("senderSig")));
                            s.update(transaction.getString("timestamp").getBytes());
                            if (s.verify(Base64.getDecoder().decode(transaction.getString("sig")))) {
                                Client.callbackError(server, "Failed to verify transaction " + transaction.getString("id"), opid);
                                return;
                            }
                        } catch (InvalidKeyException | SignatureException e) {
                            e.printStackTrace();
                        }
                    } else {
                        // Transaction comes from a send operation
                        try {
                            s = verifySignature(publicKey);
                            s.update(transaction.getJSONObject("from").getString("keyHash").getBytes());
                            s.update(transaction.getJSONObject("to").getString("keyHash").getBytes());
                            s.update(BigInteger.valueOf(transaction.getInt("amount")).toByteArray());
                            s.update(transaction.getString("previousTransaction").getBytes());
                            s.update(transaction.getString("timestamp").getBytes());
                            if (!s.verify(Base64.getDecoder().decode(transaction.getString("sig")))) {
                                Client.callbackError(server, "Failed to verify transaction " + transaction.getString("id"), opid);
                                return;
                            }
                        } catch (InvalidKeyException | SignatureException e) {
                            e.printStackTrace();
                        }
                    }
                    transactionList.addFirst(t);
                }
                Client.callbackAudit(server, transactionList, jsonResponse.getBody(), opid);
                return;
            } else {
                Client.callbackError(server, "Unexpected status code: " + jsonResponse.getStatus(), opid);
                return;
            }
        } catch (UnirestException e) {
            Client.callbackError(server, e.getMessage(), opid);
            return;
        }
    }
}
