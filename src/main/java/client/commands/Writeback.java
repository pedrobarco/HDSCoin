package client.commands;

import client.Client;
import client.domain.Server;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import java.util.Base64;

import static client.Client.debug;
import static client.ClientCrypto.checkServerSignature;
import static client.ClientCrypto.prettyPrintJsonString;

public class Writeback implements Runnable {
    private Server server;
    private String publicKeyHash;
    private JsonNode json;
    private String timestamp;
    private int opid;

    public Writeback(Server server, String publicKeyHash, JsonNode json, String timestamp, int opid){
        this.server = server;
        this.publicKeyHash = publicKeyHash;
        this.json = json;
        this.timestamp = timestamp;
        this.opid = opid;
    }

    @Override
    public void run() {
        String address = server.getAddress() + "/hds/wb";
        String transactionList = null;
        if (json != null) {
            transactionList = prettyPrintJsonString(json);
        }
        try {
            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("key", publicKeyHash)
                    .field("transactionList", transactionList)
                    .field("timestamp", timestamp)
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
                Client.callbackWriteback(server, "ACK", opid);
            }
            else {
                Client.callbackError(server, "Unexpected status code: " + jsonResponse.getStatus(), opid);
            }
        } catch (UnirestException e) {
            Client.callbackError(server, e.getMessage(), opid);
            return;
        }
    }
}
