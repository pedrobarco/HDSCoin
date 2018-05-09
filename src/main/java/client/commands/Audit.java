package client.commands;

import client.Client;
import client.domain.Server;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.json.JSONArray;

import java.text.SimpleDateFormat;
import java.util.Date;

import static client.Client.debug;
import static client.ClientCrypto.*;

@SuppressWarnings("Duplicates")
public class Audit implements Runnable {
    private Server server;
    private String publicKeyHash;

    public Audit(Server server, String publicKeyHash){
        this.server = server;
        this.publicKeyHash = publicKeyHash;
    }

    @Override
    public void run() {
        String address = server.getAddress() + "/hds/"+urlEncode(publicKeyHash)+"/audit";
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        if (debug) {
            System.out.println("--- Sending ---");
            System.out.println("Address: " + address);
            System.out.println("Account Hash: " + publicKeyHash);
            System.out.println("---------------");
        }

        try {
            HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
                    .header("accept", "application/json")
                    .field("timestamp", timestamp)
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
            else if (jsonResponse.getStatus() == 200) {
                System.out.println("Transaction list: ");
                JSONArray array = jsonResponse.getBody().getObject().getJSONArray("transactions");
                for(int i = 0; i< array.length(); i++){
                    System.out.println(prettyPrintTransaction(array.getJSONObject(i)));
                    System.out.println();
                }
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
