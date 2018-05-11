package server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import server.domain.Account;
import server.domain.AccountState;
import server.domain.Transaction;
import io.javalin.Javalin;
import io.javalin.LogLevel;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import static server.Application.generateKey;
import static server.Application.signMessage;
import static server.Application.urlDecode;

@SuppressWarnings("Duplicates")
public class MaliciousApplication {
    private static PrivateKey serverPrivkey;
    private static PublicKey serverPubkey;
    private static String address;
    public static int port;

    private static String registerHandler = "Return error";
    private static String sendHandler = "Return error";
    private static String receiveHandler = "Return error";
    private static String checkHandler = "Return error";
    private static String auditHandler = "Return error";
    private static String writebackHandler = "Return error";

    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Please specify the port");
            return;
        }
        port = Integer.valueOf(args[0]);
        generateKey();
        try {
            address = InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        Javalin app = Javalin.create().requestLogLevel(LogLevel.OFF).port(port).start();

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
            Account account = HDSLib.getInstance().register(HDSCrypto.stringToPublicKey(key), ctx.formParam("timestamp"), sig);
            System.out.println("[Register Command]");
            switch (registerHandler) {
                case "Return error":
                    System.out.println("Returned error");
                    System.out.println();
                    throw new Exception("I'm an EVIL server!");
                case "Return success":
                    System.out.println("Returned success");
                    System.out.println();
                    AccountState state = HDSLib.getInstance().checkAccount(account.getKeyHash());
                    ctx.status(201);
                    ctx.json(signMessage(state, ctx.formParam("timestamp")));
                    break;
            }
        });

        // Check Account
        app.post("/hds/:key/check", ctx -> {
            String key = urlDecode(ctx.param("key"));
            AccountState accountState = HDSLib.getInstance().checkAccount(key);
            System.out.println("[Check Command]");
            switch (checkHandler) {
                case "Return error":
                    System.out.println("Returned error");
                    System.out.println();
                    throw new Exception("I'm an EVIL server!");
                case "Return correct":
                    System.out.println("Returned correct values");
                    System.out.println();
                    ctx.status(200);
                    ctx.json(signMessage(accountState, ctx.formParam("timestamp")));
                    break;
                case "Return fake amount and no pending":
                    System.out.println("Returned a fake amount");
                    System.out.println();
                    ctx.status(200);
                    ctx.json(signMessage(new AccountState(key, 666, new LinkedList<>()), ctx.formParam("timestamp")));
                    break;
                case "Invalid server signature":
                    System.out.println("Gave invalid server signature");
                    System.out.println();
                    ctx.status(200);
                    ctx.json(accountState);
                    break;
            }
        });

        // Audit
        app.post("/hds/:key/audit", ctx -> {
            String key = urlDecode(ctx.param("key"));
            List<Transaction> transactions = HDSLib.getInstance().audit(key);
            ObjectMapper mapper = new ObjectMapper();
            ArrayNode tnode;
            JsonNode message;
            System.out.println("[Audit Command]");
            switch (auditHandler) {
                case "Return error":
                    System.out.println("Returned error");
                    System.out.println();
                    throw new Exception("I'm an EVIL server!");
                case "Return correct":
                    System.out.println("Returned correct value");
                    System.out.println();
                    ctx.status(200);
                    tnode = mapper.valueToTree(transactions);
                    message = mapper.createObjectNode().set("transactions", tnode);
                    ctx.json(signMessage(message, ctx.formParam("timestamp")));
                    break;
                case "Remove last transaction":
                    System.out.println("Removed last transaction");
                    System.out.println();
                    ctx.status(200);
                    transactions.remove(transactions.size()-1);
                    tnode = mapper.valueToTree(transactions);
                    message = mapper.createObjectNode().set("transactions", tnode);
                    ctx.json(signMessage(message, ctx.formParam("timestamp")));
                    break;
                case "Duplicate last transaction":
                    System.out.println("Duplicated last transaction");
                    System.out.println();
                    ctx.status(200);
                    transactions.add(transactions.get(transactions.size()-1));
                    tnode = mapper.valueToTree(transactions);
                    message = mapper.createObjectNode().set("transactions", tnode);
                    ctx.json(signMessage(message, ctx.formParam("timestamp")));
                    break;
            }
        });

        // Send Transaction
        app.post("/hds/:key/send", ctx -> {
            String sourceKey = urlDecode(ctx.param("key"));
            String destKey = ctx.formParam("destKey");
            int amount = Integer.parseInt(Objects.requireNonNull(ctx.formParam("amount")));
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            String previousTransaction = ctx.formParam("previousTransaction");
            Transaction transaction = HDSLib.getInstance().sendAmount(sourceKey, destKey,  amount, previousTransaction, ctx.formParam("timestamp"), sig);
            System.out.println("[Send Command]");
            switch (sendHandler) {
                case "Return error":
                    System.out.println("Returned error");
                    System.out.println();
                    throw new Exception("I'm an EVIL server!");
                case "Return success":
                    System.out.println("Returned success");
                    System.out.println();
                    ctx.status(201);
                    ctx.json(signMessage(transaction, ctx.formParam("timestamp")));
                    break;
            }
        });

        // Receive Transaction
        app.post("/hds/receive/:id", ctx -> {
            String id = ctx.param("id");
            byte[] transactionSig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("transactionSig")));
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            String previousTransaction = ctx.formParam("previousTransaction");
            Transaction transaction = HDSLib.getInstance().receiveAmount(id, transactionSig, previousTransaction, ctx.formParam("timestamp"), sig);
            System.out.println("[Receive Command]");
            switch (receiveHandler) {
                case "Return error":
                    System.out.println("Returned error");
                    System.out.println();
                    throw new Exception("I'm an EVIL server!");
                case "Return success":
                    System.out.println("Returned success");
                    System.out.println();
                    ctx.status(201);
                    ctx.json(signMessage(transaction, ctx.formParam("timestamp")));
                    break;
            }
        });

        // Ping
        app.post("/hds/ping", ctx -> {
            ctx.status(200);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode ping = mapper.createObjectNode().put("ping", "ping");
            ctx.json(signMessage(ping, ctx.formParam("timestamp")));
        });

        // Receive a writeback
        app.post("/hds/wb", ctx -> {
            String key = ctx.formParam("key");
            if (ctx.formParam("transactionList") != null) {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode transactions = mapper.readTree(ctx.formParam("transactionList"));
                HDSLib.getInstance().joinLedger(key, transactions);
            }
            System.out.println("[Writeback Command]");
            switch (receiveHandler) {
                case "Return error":
                    System.out.println("Returned error");
                    System.out.println();
                    throw new Exception("I'm an EVIL server!");
                case "Return success":
                    System.out.println("Returned success");
                    System.out.println();
                    ctx.status(201);
                    ObjectMapper mapper = new ObjectMapper();
                    ObjectNode ping = mapper.createObjectNode().put("ack", "ack");
                    ctx.json(signMessage(ping, ctx.formParam("timestamp")));
                    break;
            }
        });

        Application.announceSelf();
        System.out.println("--- \uD83D\uDC80 EVIL Server ---");
        System.out.println("\nServer listening on " + address + " at port " + port);
        while (true) {
            printHandlers();
            System.out.print("> ");
            Scanner scanner = new Scanner(System.in);
            String c = scanner.nextLine();
            switch (c) {
                case "1":
                    selectRegisterHandler();
                    break;
                case "2":
                    selectSendHandler();
                    break;
                case "3":
                    selectReceiveHandler();
                    break;
                case "4":
                    selectCheckHandler();
                    break;
                case "5":
                    selectAuditHandler();
                    break;
                case "6":
                    selectWritebackHandler();
                    break;
                default:
                    break;
            }
        }
    }

    private static void printHandlers() {
        System.out.println("1 - On Register: " + registerHandler);
        System.out.println("2 - On Send: " + sendHandler);
        System.out.println("3 - On Receive: " + receiveHandler);
        System.out.println("4 - On Check: " + checkHandler);
        System.out.println("5 - On Audit: " + auditHandler );
        System.out.println("6 - On Writeback: " + writebackHandler);
    }

    private static void selectRegisterHandler() {
        System.out.println("1 - Return error");
        System.out.println("2 - Return success");
        System.out.print("> ");
        Scanner scanner = new Scanner(System.in);
        String c = scanner.nextLine();
        switch (c) {
            case "2":
                registerHandler = "Return success";
                break;
            default:
                registerHandler = "Return error";
                break;
        }
    }

    private static void selectSendHandler() {
        System.out.println("1 - Return error");
        System.out.println("2 - Return success");
        System.out.print("> ");
        Scanner scanner = new Scanner(System.in);
        String c = scanner.nextLine();
        switch (c) {
            case "2":
                sendHandler = "Return success";
                break;
            default:
                sendHandler = "Return error";
                break;
        }
    }

    private static void selectReceiveHandler() {
        System.out.println("1 - Return error");
        System.out.println("2 - Return success");
        System.out.print("> ");
        Scanner scanner = new Scanner(System.in);
        String c = scanner.nextLine();
        switch (c) {
            case "2":
                receiveHandler = "Return success";
                break;
            default:
                receiveHandler = "Return error";
                break;
        }
    }

    private static void selectCheckHandler() {
        System.out.println("1 - Return error");
        System.out.println("2 - Return correct");
        System.out.println("3 - Return fake amount and no pending");
        System.out.println("4 - Invalid server signature");
        System.out.print("> ");
        Scanner scanner = new Scanner(System.in);
        String c = scanner.nextLine();
        switch (c) {
            case "2":
                checkHandler = "Return correct";
                break;
            case "3":
                checkHandler = "Return fake amount and no pending";
                break;
            case "4":
                checkHandler = "Invalid server signature";
            default:
                checkHandler = "Return error";
                break;
        }
    }

    private static void selectAuditHandler() {
        System.out.println("1 - Return error");
        System.out.println("2 - Return correct");
        System.out.println("3 - Remove last transaction");
        System.out.println("4 - Duplicate last transaction");
        System.out.print("> ");
        Scanner scanner = new Scanner(System.in);
        String c = scanner.nextLine();
        switch (c) {
            case "2":
                auditHandler = "Return correct";
                break;
            case "3":
                auditHandler = "Remove last transaction";
                break;
            case "4":
                auditHandler = "Duplicate last transaction";
                break;
            default:
                auditHandler = "Return error";
                break;
        }
    }

    private static void selectWritebackHandler() {
        System.out.println("1 - Return error");
        System.out.println("2 - Return success");
        System.out.print("> ");
        Scanner scanner = new Scanner(System.in);
        String c = scanner.nextLine();
        switch (c) {
            case "2":
                writebackHandler = "Return success";
                break;
            default:
                writebackHandler = "Return error";
                break;
        }
    }
}
