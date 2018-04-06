import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import domain.Account;
import domain.AccountState;
import domain.Transaction;
import io.javalin.Javalin;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Objects;

public class Application {
    private static PrivateKey serverPrivkey;
    private static PublicKey serverPubkey;

    public static ObjectNode signMessage(Object message, String timestamp) throws Exception{
        Signature s = HDSCrypto.createSignature(serverPrivkey);
        s.update(timestamp.getBytes());
        String signature = new String(Base64.getEncoder().encode(s.sign()));
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode msg = mapper.valueToTree(message);
        msg.put("serverSig", signature);
        return msg;
    }

    public static void main(String[] args) {
        generateKey();
        Javalin app = Javalin.start(8080);

        app.exception(Exception.class, (e, ctx) -> {
            // handle general exceptions here
            // will not trigger if more specific exception-mapper found
            e.printStackTrace();
            ctx.status(400);
            try {
                ctx.json(signMessage(e, ctx.formParam("timestamp")));
            } catch (Exception e1) {
                // Ok, you got me here
                System.out.println("FATAL ERROR SORRY");
            }
        });

        // Register
        app.post("/hds/", ctx -> {
            String key = ctx.formParam("key");
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            Date timestamp = HDSCrypto.stringToDate(ctx.formParam("timestamp"));
            Account account = HDSLib.getInstance().register(HDSCrypto.stringToPublicKey(key), timestamp, sig);
            if (account == null) {
                ctx.status(500);
                //ctx.result("Error registering account.");
            } else {
                AccountState state = HDSLib.getInstance().checkAccount(account.getKeyHash());
                ctx.status(201);
                ctx.json(signMessage(state, ctx.formParam("timestamp")));
            }
        });

        // Get Account
        /*app.get("/hds/:key", ctx -> {
            String key = ctx.param("key");
            Account account = HDSLib.getInstance().getAccount(key);
            if (account == null) {
                ctx.status(404);
                ctx.result("Account not found.");
            } else {
                ctx.status(200);
                ctx.json(account);
            }
        });*/

        // Check Account
        app.post("/hds/:key/check", ctx -> {
            String key = urlDecode(ctx.param("key"));
            AccountState accountState = HDSLib.getInstance().checkAccount(key);
            if (accountState == null) {
                ctx.status(500);
                //ctx.result("Couldn't get account state.");
            } else {
                ctx.status(200);
                ctx.json(signMessage(accountState, ctx.formParam("timestamp")));
            }
        });

        // Audit
        app.post("/hds/:key/audit", ctx -> {
            String key = urlDecode(ctx.param("key"));
            List<Transaction> transactions = HDSLib.getInstance().audit(key);
            if (transactions == null) {
                ctx.status(404);
                //ctx.result("Make sure you audit a valid account/key.");
            } else {
                ctx.status(200);
                ObjectMapper mapper = new ObjectMapper();
                ArrayNode tnode = mapper.valueToTree(transactions);
                JsonNode message = mapper.createObjectNode().set("transactions", tnode);
                ctx.json(signMessage(message, ctx.formParam("timestamp")));
            }
        });

        // Send Transaction
        app.post("/hds/:key/send", ctx -> {
            String sourceKey = urlDecode(ctx.param("key"));
            String destKey = ctx.formParam("destKey");
            int amount = Integer.parseInt(Objects.requireNonNull(ctx.formParam("amount")));
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            Date timestamp = HDSCrypto.stringToDate(ctx.formParam("timestamp"));
            Transaction transaction = HDSLib.getInstance().sendAmount(sourceKey, destKey,  amount, timestamp, sig);
            if (transaction == null) {
                ctx.status(500);
                //ctx.result("Error sending coins.");
            } else {
                ctx.status(201);
                ctx.json(signMessage(transaction, ctx.formParam("timestamp")));
            }
        });

        // Receive Transaction
        app.post("/hds/receive/:id", ctx -> {
            int id = Integer.parseInt(Objects.requireNonNull(ctx.param("id")));
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            Date timestamp = HDSCrypto.stringToDate(ctx.formParam("timestamp"));
            Transaction transaction = HDSLib.getInstance().receiveAmount(id, timestamp, sig);
            if (transaction == null) {
                ctx.status(500);
                //ctx.result("Error confirming transaction.");
            } else {
                ctx.status(201);
                ctx.json(signMessage(transaction, ctx.formParam("timestamp")));
            }
        });

        // Ping
        app.post("/hds/ping", ctx -> {
            ctx.status(200);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode ping = mapper.createObjectNode().put("ping", "ping");
            ctx.json(signMessage(ping, ctx.formParam("timestamp")));
        });
    }

    private static void generateKey() {
        if (new File("server.priv").isFile()) {
            // Open keys from file
            try {
                byte[] privkeyBytes = Files.readAllBytes(Paths.get("server.priv"));
                PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privkeyBytes);
                KeyFactory factory = KeyFactory.getInstance("EC", "SunEC");
                serverPrivkey = factory.generatePrivate(privSpec);
            } catch (IOException e) {
                e.printStackTrace();
                return;
            } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
                e.printStackTrace();
                return;
            }
        } else {
            // Generate new keys
            KeyPair pair = HDSCrypto.generateKeypairEC();
            serverPrivkey = pair.getPrivate();
            serverPubkey = pair.getPublic();

            try {
                FileOutputStream fos = new FileOutputStream("server.pub");
                fos.write(serverPubkey.getEncoded());
                fos.close();

                fos = new FileOutputStream("server.priv");
                fos.write(serverPrivkey.getEncoded());
                fos.close();
            } catch (java.io.IOException e) {
                e.printStackTrace();
            }
        }
    }

    private static String urlDecode(String encoded) {
        return encoded.replace(".","+").replace("_","/").replace("-","=");
    }
}
