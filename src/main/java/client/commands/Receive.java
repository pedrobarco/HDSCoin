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
    private PrivateKey privateKey;

    public Receive(Server server, String transactionID, String transactionSig, PrivateKey privateKey){
        this.server = server;
        this.transactionID = transactionID;
        this.transactionSig = transactionSig;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());

        Signature s = null;
        byte[] sig = null;
        try {
            s = createSignature(privateKey);
            s.update(BigInteger.valueOf(Integer.parseInt(transactionID)).toByteArray());
            s.update(Base64.getDecoder().decode(transactionSig));
            s.update(timestamp.getBytes());
            sig = s.sign();
        } catch (InvalidKeyException | SignatureException e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        String encodedSig = new String(Base64.getEncoder().encode(sig));
        String address = server.getAddress() + "/hds/receive/"+transactionID;

        if (debug) {
            System.out.println("--- Sending ---");
            System.out.println("Address: " + address);
            System.out.println("Transaction ID: " + transactionID);
            System.out.println("Transaction Sig: " + transactionSig);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("Sig: " + encodedSig);
            System.out.println("---------------");
        }

        try {
            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("id", transactionID)
                    .field("transactionSig", transactionSig)
                    .field("timestamp", timestamp)
                    .field("sig", encodedSig)
                    .asJson();

            if (debug) {
                System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
            }

            if (!checkServerSignature(jsonResponse.getBody(), timestamp, server.getPublicKey())) {
                System.out.println("[ERROR] Could not verify the server's signature");
            }
            else if (jsonResponse.getStatus() == 400){
                System.out.println("[ERROR] " + jsonResponse.getBody().getObject().get("message"));
            }
            else if (jsonResponse.getStatus() == 201) {
                System.out.println("Received successfully! Amount received: " + jsonResponse.getBody().getObject().get("amount"));
            }
            else {
                System.out.println("[ERROR] Unexpected status code: " + jsonResponse.getStatus());
            }

            Client.callback(jsonResponse.getStatus());
        } catch (UnirestException e) {
            e.printStackTrace();
        }
    }
}
