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
    private String timestamp;
    private String sig;
    private int opid;

    public Register(Server server, PublicKey publicKey, String timestamp, String sig, int opid){
        this.publicKey = publicKey;
        this.server = server;
        this.timestamp = timestamp;
        this.sig = sig;
        this.opid = opid;
    }

    @Override
    public void run() {
        try {
            String publicKeyString = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
            String address = server.getAddress() + "/hds/";

            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("key", publicKeyString)
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
                Client.callbackRegister(server,"Registered successfully! Your hash: " + jsonResponse.getBody().getObject().get("keyHash"), opid);
            }
            else {
                Client.callbackError(server, "Unexpected status code: " + jsonResponse.getStatus(), opid);
            }
        } catch (UnirestException e) {
            Client.callbackError(server, e.getMessage(), opid);
            return;
        }
    }

    public static String sign(PublicKey publicKey, String timestamp, PrivateKey privateKey){
        String publicKeyString = new String(Base64.getEncoder().encode(publicKey.getEncoded()));

        Signature s = null;
        byte[] sig = null;
        try {
            s = createSignature(privateKey);
            s.update(timestamp.getBytes());
            sig = s.sign();
        } catch (InvalidKeyException | SignatureException e) {
            System.out.println("[ERROR] " + e.getMessage());
            return null;
        }

        return new String(Base64.getEncoder().encode(sig));
    }
}
