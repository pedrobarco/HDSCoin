package client.commands;

import client.Client;
import client.domain.Server;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.math.BigInteger;
import java.security.*;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;

import static client.Client.debug;
import static client.ClientCrypto.*;

@SuppressWarnings("Duplicates")
public class Send implements Runnable{
    private Server server;
    private String source;
    private String dest;
    private String amount;
    private String previousTransaction;
    private String timestamp;
    private String sig;

    public Send(Server server, String source, String dest, String amount, String previousTransaction, String timestamp, String sig){
        this.server = server;
        this.source = source;
        this.dest = dest;
        this.amount = amount;
        this.previousTransaction = previousTransaction;
        this.timestamp = timestamp;
        this.sig = sig;
    }

    @Override
    public void run() {
        String address = server.getAddress() + "/hds/"+urlEncode(source)+"/send";

        try {
            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("destKey", dest)
                    .field("amount", amount)
                    .field("timestamp", timestamp)
                    .field("previousTransaction", previousTransaction)
                    .field("sig", sig)
                    .asJson();

            if (debug == Client.debugMode.VERBOSE) {
                System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
            }

            if (!checkServerSignature(jsonResponse.getBody(), timestamp, server.getPublicKey())) {
                Client.callbackError(server, "Could not verify the server's signature");
            }
            else if (jsonResponse.getStatus() == 400){
                Client.callbackError(server, jsonResponse.getBody().getObject().getString("message"));
            }
            else if (jsonResponse.getStatus() == 201) {
                Client.callbackSend(server, "Sent successfully! Transaction id: " + jsonResponse.getBody().getObject().get("id"));
            }
            else {
                Client.callbackError(server, "Unexpected status code: " + jsonResponse.getStatus());
            }
        } catch (UnirestException e) {
            Client.callbackError(server, e.getMessage());
            return;
        }
    }

    public static String sign(String source, String dest, String amount, String previousTransaction, String timestamp, PrivateKey privateKey){
        Signature s = null;
        byte[] sig = null;
        try {
            s = createSignature(privateKey);
            s.update(source.getBytes());
            //System.out.println("[HEREC] from: " + source);
            s.update(dest.getBytes());
            //System.out.println("[HEREC] to: " + dest);
            s.update(BigInteger.valueOf(Integer.parseInt(amount)).toByteArray());
            //System.out.println("[HEREC] amount: " + amount);
            s.update(previousTransaction.getBytes());
            //System.out.println("[HEREC] prevTrans: " + previousTransaction);
            s.update(timestamp.getBytes());
            //System.out.println("[HEREC] timestamp: " + timestamp);
            sig = s.sign();
        } catch (InvalidKeyException | SignatureException e) {
            System.out.println("[ERROR] " + e.getMessage());
            return null;
        }

        return new String(Base64.getEncoder().encode(sig));
    }
}
