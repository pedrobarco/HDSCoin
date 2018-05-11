package client.commands;

import client.Client;
import client.domain.Server;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import static client.Client.debug;
import static client.ClientCrypto.checkServerSignature;
import static client.ClientCrypto.createSignature;
import static client.ClientCrypto.prettyPrintJsonString;

@SuppressWarnings("Duplicates")
public class Receive implements Runnable {
    private Server server;
    private String transactionID;
    private String transactionSig;
    private String timestamp;
    private String sig;
    private String previousTransaction;
    private int opid;

    public Receive(Server server, String transactionID, String transactionSig, String previousTransaction, String timestamp, String sig, int opid){
        this.server = server;
        this.transactionID = transactionID;
        this.transactionSig = transactionSig;
        this.timestamp = timestamp;
        this.sig = sig;
        this.previousTransaction = previousTransaction;
        this.opid = opid;
    }

    @Override
    public void run() {
        String address = server.getAddress() + "/hds/receive/"+transactionID;

        try {
            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("id", transactionID)
                    .field("transactionSig", transactionSig)
                    .field("previousTransaction", previousTransaction)
                    .field("timestamp", timestamp)
                    .field("sig", sig)
                    .asJson();

            if (debug == Client.debugMode.VERBOSE) {
                System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
            }

            if (!checkServerSignature(jsonResponse.getBody(), timestamp, server.getPublicKey())) {
                Client.callbackError(server, "Could not verify the server's signature", opid);
            }
            else if (jsonResponse.getStatus() == 400){
                Client.callbackError(server, jsonResponse.getBody().getObject().getString("message"), opid);
            }
            else if (jsonResponse.getStatus() == 201) {
                Client.callbackReceive(server, "Received successfully! Amount received: " + jsonResponse.getBody().getObject().get("amount"), opid);
            }
            else {
                Client.callbackError(server, "Unexpected status code: " + jsonResponse.getStatus(), opid);
            }
        } catch (UnirestException e) {
            Client.callbackError(server, e.getMessage(), opid);
            return;
        }
    }

    public static String sign(String transactionID, String transactionSig, String previousTransaction, String timestamp, PrivateKey privateKey){
        Signature s = null;
        byte[] sig = null;
        try {
            s = createSignature(privateKey);
            s.update(transactionID.getBytes());
            s.update(Base64.getDecoder().decode(transactionSig));
            s.update(previousTransaction.getBytes());
            s.update(timestamp.getBytes());
            sig = s.sign();
        } catch (InvalidKeyException | SignatureException e) {
            System.out.println("[ERROR] " + e.getMessage());
            return null;
        }

        return new String(Base64.getEncoder().encode(sig));
    }
}
