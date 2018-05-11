package client.commands;

import client.Client;
import client.domain.Account;
import client.domain.Server;
import client.domain.Transaction;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

import static client.Client.debug;
import static client.ClientCrypto.*;

@SuppressWarnings("Duplicates")
public class Check implements Runnable {
    private Server server;
    private String publicKeyHash;
    private String timestamp;
    private int opid;

    public Check(Server server, String publicKeyHash, String timestamp, int opid){
        this.server = server;
        this.publicKeyHash = publicKeyHash;
        this.timestamp = timestamp;
        this.opid = opid;
    }

    @Override
    public void run() {
        String address = server.getAddress() + "/hds/"+urlEncode(publicKeyHash)+"/check";

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
            }

            else if (jsonResponse.getStatus() == 400){
                Client.callbackError(server, jsonResponse.getBody().getObject().getString("message"), opid);
            }
            else if (jsonResponse.getStatus() == 200) {
                JSONArray array = jsonResponse.getBody().getObject().getJSONArray("pendingTransactions");
                Map<String, Transaction> pendingTransactions = new HashMap<>();
                for(int i = 0; i< array.length(); i++){
                    JSONObject transaction = array.getJSONObject(i);
                    Transaction t = new Transaction(transaction.getString("id"),
                            transaction.getJSONObject("from").getString("keyHash"),
                            transaction.getJSONObject("to").getString("keyHash"),
                            transaction.getInt("amount"),
                            transaction.getString("sig"),
                            transaction.getString("transactionHash"));
                    pendingTransactions.put(transaction.getString("id"), t);
                }
                Client.callbackCheck(server,new Account(jsonResponse.getBody().getObject().getInt("amount"), pendingTransactions), opid);
            }
            else {
                Client.callbackError(server,"Unexpected status code: " + jsonResponse.getStatus(), opid);
            }
        } catch (UnirestException e) {
            Client.callbackError(server, e.getMessage(), opid);
            return;
        }
    }
}
