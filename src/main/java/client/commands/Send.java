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
import static client.ClientCrypto.checkServerSignature;
import static client.ClientCrypto.createSignature;
import static client.ClientCrypto.urlEncode;
import static client.LegacyClient.prettyPrintJsonString;

@SuppressWarnings("Duplicates")
public class Send implements Runnable{
    private Server server;
    private String source;
    private String dest;
    private String amount;
    private PrivateKey privateKey;

    public Send(Server server, String source, String dest, String amount, PrivateKey privateKey){
        this.server = server;
        this.source = source;
        this.dest = dest;
        this.amount = amount;
        this.privateKey = privateKey;
    }

    @Override
    public void run() {
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());

        Signature s = null;
        byte[] sig = null;
        try {
            s = createSignature(privateKey);
            s.update(source.getBytes());
            s.update(dest.getBytes());
            s.update(BigInteger.valueOf(Integer.parseInt(amount)).toByteArray());
            s.update(timestamp.getBytes());
            sig = s.sign();
        } catch (InvalidKeyException | SignatureException e) {
            System.out.println("[ERROR] " + e.getMessage());
            return;
        }

        String encodedSig = new String(Base64.getEncoder().encode(sig));
        String address = server.getAddress() + "/hds/"+urlEncode(source)+"/send";

        if (debug) {
            System.out.println("--- Sending ---");
            System.out.println("Address: " + address);
            System.out.println("Source hash: " + source);
            System.out.println("Destination hash: " + dest);
            System.out.println("Amount: " + amount);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("Sig: " + encodedSig);
            System.out.println("---------------");
        }

        try {
            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("destKey", dest)
                    .field("amount", amount)
                    .field("timestamp", timestamp)
                    .field("sig", encodedSig)
                    .asJson();

            if (debug) {
                System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
            }

            else if (!checkServerSignature(jsonResponse.getBody(), timestamp, server.getPublicKey())) {
                System.out.println("[ERROR] Could not verify the server's signature");
            }
            else if (jsonResponse.getStatus() == 400){
                System.out.println("[ERROR] " + jsonResponse.getBody().getObject().get("message"));
            }
            else if (jsonResponse.getStatus() == 201) {
                System.out.println("Sent successfully! Transaction id: " + jsonResponse.getBody().getObject().get("id"));
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
