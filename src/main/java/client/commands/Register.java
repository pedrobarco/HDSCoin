package client.commands;

import client.Client;
import client.domain.Server;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import static client.ClientCrypto.checkServerSignature;
import static client.ClientCrypto.createSignature;
import static client.ClientCrypto.prettyPrintJsonString;
import static client.Client.debug;

@SuppressWarnings("Duplicates") // TODO: Check all Duplicates after Legacy Client removal, only remove this comment when done
public class Register implements Runnable {
    private Server server;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public Register(Server server, PublicKey publicKey, PrivateKey privateKey){
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.server = server;
    }

    @Override
    public void run() {
        // TODO: Printing like it is being done is bad in a threaded environment
        String publicKeyString = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());

        Signature s = null;
        byte[] sig = null;
        try {
            s = createSignature(privateKey);
            s.update(timestamp.getBytes());
            sig = s.sign();
        } catch (InvalidKeyException | SignatureException e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        String encodedSig = new String(Base64.getEncoder().encode(sig));
        String address = server.getAddress() + "/hds/";
        if (debug) {
            System.out.println("--- Sending ---");
            System.out.println("Address: " + address);
            System.out.println("Public key: " + publicKeyString);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("Sig: " + encodedSig);
            System.out.println("---------------");
        }

        try {
            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("key", publicKeyString)
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
                System.out.println("Registered successfully! Your hash: " + jsonResponse.getBody().getObject().get("keyHash"));
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
