import domain.Account;
import domain.AccountState;
import domain.Transaction;
import io.javalin.Javalin;

import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Objects;

public class Application {
    public static void main(String[] args) {
        Javalin app = Javalin.start(8080);

        app.exception(Exception.class, (e, ctx) -> {
            // handle general exceptions here
            // will not trigger if more specific exception-mapper found
            e.printStackTrace();
            ctx.status(400);
            ctx.json(e);
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
                ctx.status(201);
                ctx.json(HDSLib.getInstance().checkAccount(account.getKeyHash()));
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
        app.get("/hds/:key/check", ctx -> {
            String key = urlDecode(ctx.param("key"));
            AccountState accountState = HDSLib.getInstance().checkAccount(key);
            if (accountState == null) {
                ctx.status(500);
                ctx.result("Couldn't get account state.");
            } else {
                ctx.status(200);
                ctx.json(accountState);
            }
        });

        // Audit
        app.get("/hds/:key/audit", ctx -> {
            String key = urlDecode(ctx.param("key"));
            List<Transaction> transactions = HDSLib.getInstance().audit(key);
            if (transactions == null) {
                ctx.status(404);
                ctx.result("Make sure you audit a valid account/key.");
            } else {
                ctx.status(200);
                ctx.json(transactions);
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
                ctx.result("Error sending coins.");
            } else {
                ctx.status(201);
                ctx.json(transaction);
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
                ctx.result("Error confirming transaction.");
            } else {
                ctx.status(201);
                ctx.json(transaction);
            }
        });

        // Ping
        app.get("/hds/ping", ctx -> {
            ctx.status(200);
        });
    }

    private static String urlDecode(String encoded) {
        return encoded.replace(".","+").replace("_","/").replace("-","=");
    }
}
