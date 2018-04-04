import com.j256.ormlite.dao.ForeignCollection;
import domain.Account;
import domain.AccountState;
import domain.Transaction;
import io.javalin.Javalin;

import java.util.Base64;
import java.util.Date;
import java.util.Objects;

public class Application {
    public static void main(String[] args) {
        Javalin app = Javalin.start(8080);

        app.exception(Exception.class, (e, ctx) -> {
            // handle general exceptions here
            // will not trigger if more specific exception-mapper found
            ctx.status(400);
            ctx.result(e.getMessage());
        });

        app.post("/hds/", ctx -> {
            String key = ctx.formParam("key");
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            Date timestamp = HDSCrypto.StringToDate(ctx.formParam("timestamp"));
            Account account = HDSLib.getInstance().register(key, timestamp, sig);
            if (account == null) {
                ctx.status(500);
                ctx.result("Error registering account.");
            } else {
                ctx.status(201);
                ctx.json(account);
            }
        });

        app.get("/hds/:key", ctx -> {
            String key = ctx.param("key");
            Account account = HDSLib.getInstance().getAccount(key);
            if (account == null) {
                ctx.status(404);
                ctx.result("Account not found.");
            } else {
                ctx.status(200);
                ctx.json(account);
            }
        });

        app.get("/hds/:key/check", ctx -> {
            String key = ctx.param("key");
            AccountState accountState = HDSLib.getInstance().checkAccount(key);
            if (accountState == null) {
                ctx.status(404);
                ctx.result("Make sure you check a valid account/key.");
            } else {
                ctx.status(200);
                ctx.json(accountState);
            }
        });

        app.get("/hds/:key/audit", ctx -> {
            String key = ctx.param("key");
            ForeignCollection<Transaction> transactions = HDSLib.getInstance().audit(key);
            if (transactions == null) {
                ctx.status(404);
                ctx.result("Make sure you audit a valid account/key.");
            } else {
                ctx.status(200);
                ctx.json(transactions);
            }
        });

        app.post("/hds/:key/send", ctx -> {
            String sourceKey = ctx.param("key");
            String destKey = ctx.formParam("destKey");
            int amount = Integer.parseInt(Objects.requireNonNull(ctx.formParam("amount")));
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            Date timestamp = HDSCrypto.StringToDate(ctx.formParam("timestamp"));
            Transaction transaction = HDSLib.getInstance().sendAmount(sourceKey, destKey,  amount, timestamp, sig);
            if (transaction == null) {
                ctx.status(500);
                ctx.result("Error sending coins.");
            } else {
                ctx.status(201);
                ctx.json(transaction);
            }
        });

        app.post("/hds/receive/:id", ctx -> {
            String sourceKey = ctx.formParam("sourceKey");
            String destKey = ctx.formParam("destKey");
            int id = Integer.parseInt(Objects.requireNonNull(ctx.param("id")));
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            Date timestamp = HDSCrypto.StringToDate(ctx.formParam("timestamp"));
            Transaction transaction = HDSLib.getInstance().receiveAmount(sourceKey, destKey, id, timestamp, sig);
            if (transaction == null) {
                ctx.status(500);
                ctx.result("Error confirming transaction.");
            } else {
                ctx.status(201);
                ctx.json(transaction);
            }
        });
    }
}
