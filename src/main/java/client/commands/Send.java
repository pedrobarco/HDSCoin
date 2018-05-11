package client.commands;

import client.Client;
import client.domain.Server;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;

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
    private int opid;

    public Send(Server server, String source, String dest, String amount, String previousTransaction, String timestamp, String sig, int opid){
        this.server = server;
        this.source = source;
        this.dest = dest;
        this.amount = amount;
        this.previousTransaction = previousTransaction;
        this.timestamp = timestamp;
        this.sig = sig;
        this.opid = opid;
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
                Client.callbackError(server, "Could not verify the server's signature", opid);
            }
            else if (jsonResponse.getStatus() == 400){
                Client.callbackError(server, jsonResponse.getBody().getObject().getString("message"), opid);
            }
            else if (jsonResponse.getStatus() == 201) {
                Client.callbackSend(server, "Sent successfully! Transaction id: " + jsonResponse.getBody().getObject().get("id"), opid);
            }
            else {
                Client.callbackError(server, "Unexpected status code: " + jsonResponse.getStatus(), opid);
            }
        } catch (UnirestException e) {
            Client.callbackError(server, e.getMessage(), opid);
            return;
        }
    }

    public static String sign(String source, String dest, String amount, String previousTransaction, String timestamp, PrivateKey privateKey){
        Signature s = null;
        byte[] sig = null;
        try {
            s = createSignature(privateKey);
            s.update(source.getBytes());
            s.update(dest.getBytes());
            s.update(BigInteger.valueOf(Integer.parseInt(amount)).toByteArray());
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
