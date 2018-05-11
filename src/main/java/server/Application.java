package server;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.javalin.Javalin;
import server.domain.Account;
import server.domain.AccountState;
import server.domain.Transaction;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Scanner;

import static client.ClientCrypto.generateCertificate;

@SuppressWarnings("Duplicates")
public class Application {
    private static PrivateKey serverPrivkey;
    private static PublicKey serverPubkey;
    private static String address;
    public static int port;
    private static int delay;

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
        if (args.length < 1) {
            System.out.println("Please specify the port");
            return;
        }
        if (args.length == 2) {
            delay = Integer.parseInt(args[1]);
        } else {
            delay = 0;
        }
        port = Integer.valueOf(args[0]);
        generateKey();
        try {
            address = InetAddress.getLocalHost().getHostAddress();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        Javalin app = Javalin.start(port);

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
            if (delay != 0) {
                Thread.sleep(delay*1000);
            }
            String key = ctx.formParam("key");
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            Account account = HDSLib.getInstance().register(HDSCrypto.stringToPublicKey(key), ctx.formParam("timestamp"), sig);
            if (account == null) {
                ctx.status(500);
                //ctx.result("Error registering account.");
            } else {
                AccountState state = HDSLib.getInstance().checkAccount(account.getKeyHash());
                ctx.status(201);
                ctx.json(signMessage(state, ctx.formParam("timestamp")));
            }
        });

        // Check Account
        app.post("/hds/:key/check", ctx -> {
            if (delay != 0) {
                Thread.sleep(delay*1000);
            }
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
            if (delay != 0) {
                Thread.sleep(delay*1000);
            }
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
            if (delay != 0) {
                Thread.sleep(delay*1000);
            }
            String sourceKey = urlDecode(ctx.param("key"));
            String destKey = ctx.formParam("destKey");
            int amount = Integer.parseInt(Objects.requireNonNull(ctx.formParam("amount")));
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            String previousTransaction = ctx.formParam("previousTransaction");
            Transaction transaction = HDSLib.getInstance().sendAmount(sourceKey, destKey,  amount, previousTransaction, ctx.formParam("timestamp"), sig);
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
            if (delay != 0) {
                Thread.sleep(delay*1000);
            }
            String id = ctx.param("id");
            byte[] transactionSig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("transactionSig")));
            byte[] sig = Base64.getDecoder().decode(Objects.requireNonNull(ctx.formParam("sig")));
            String previousTransaction = ctx.formParam("previousTransaction");
            Transaction transaction = HDSLib.getInstance().receiveAmount(id, transactionSig, previousTransaction, ctx.formParam("timestamp"), sig);
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
            if (delay != 0) {
                Thread.sleep(delay*1000);
            }
            ctx.status(200);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode ping = mapper.createObjectNode().put("ping", "ping");
            ctx.json(signMessage(ping, ctx.formParam("timestamp")));
        });

        // Receive a writeback
        app.post("/hds/wb", ctx -> {
            if (delay != 0) {
                Thread.sleep(delay*1000);
            }
            String key = ctx.formParam("key");
            if (ctx.formParam("transactionList") != null) {
                ObjectMapper mapper = new ObjectMapper();
                JsonNode transactions = mapper.readTree(ctx.formParam("transactionList"));
                HDSLib.getInstance().joinLedger(key, transactions);
            }
            ctx.status(201);
            ObjectMapper mapper = new ObjectMapper();
            ObjectNode ping = mapper.createObjectNode().put("ack", "ack");
            ctx.json(signMessage(ping, ctx.formParam("timestamp")));
        });

        announceSelf();
        System.out.println("\nServer listening on " + address + " at port " + port);
        System.out.println("Write \'quit\' to stop the server\n");
        while (true) {
            Scanner scanner = new Scanner(System.in);
            String c = scanner.nextLine();
            if (c.equals("quit")){
                app.stop();
                return;
            }
        }
    }

    public static void generateKey() {
        new File("keys/").mkdirs();
        if (new File("keys/s"+port+".ks").isFile()) {
            // Open keys from file
            try {
                LoadKeyStore("s"+port, "password");
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        } else {
            // Generate new keys
            GenerateKeyStore("s"+port, "password");
        }
    }

    private static void LoadKeyStore(String keyname, String password) throws FileNotFoundException {
        // Open keystore
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return;
        }
        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream("keys/"+keyname+".ks");
            ks.load(fis, password.toCharArray());
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    e.printStackTrace();
                    return;
                }
            }
        }

        // Get private key from keystore
        try {
            serverPrivkey = (PrivateKey)ks.getKey("private", password.toCharArray());
            serverPubkey = ks.getCertificate("private").getPublicKey();
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            e.printStackTrace();
        }

        // Hash public key
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
    }

    @SuppressWarnings("Duplicates")
    private static void GenerateKeyStore(String keyname, String password){
        // Create empty KeyStore
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(KeyStore.getDefaultType());
        } catch (KeyStoreException e) {
            e.printStackTrace();
            return;
        }
        try {
            ks.load(null, password.toCharArray());
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
            return;
        }

        // Generate keys
        KeyPairGenerator keyGen = null;
        SecureRandom random = null;
        try {
            keyGen = KeyPairGenerator.getInstance("EC", "SunEC");
            random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e1) {
            e1.printStackTrace();
        }
        keyGen.initialize(224, random);

        KeyPair ec = keyGen.generateKeyPair();
        PublicKey pubkey = ec.getPublic();
        PrivateKey privkey = ec.getPrivate();

        // Store private key in keystore
        try {
            java.security.cert.Certificate[] chain = {generateCertificate("cn=HDS", ec, 365, "SHA256withECDSA")};
            ks.setKeyEntry("private", privkey, password.toCharArray(), chain);
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            return;
        }

        java.io.FileOutputStream fos = null;
        try {
            fos = new java.io.FileOutputStream("keys/"+keyname+".ks", false);
            ks.store(fos, password.toCharArray());
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
            return;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        // Update key vars and hashed key
        serverPubkey = pubkey;
        serverPrivkey = privkey;
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
    }

    /* This is so clients can know what servers to talk to, and their respective public keys */
    public static void announceSelf() {
        String serverName = "s"+port;
        String ip = "http://" + address + ":" + port;
        File announcementFile = new File("servers/"+serverName);
        announcementFile.getParentFile().mkdirs();
        if (announcementFile.exists()) {
            announcementFile.delete();
        }
        try {
            FileOutputStream fos = new FileOutputStream("servers/"+serverName);
            fos.write((serverName+"\n").getBytes(Charset.forName("UTF-8")));
            fos.write((ip+"\n").getBytes(Charset.forName("UTF-8")));
            fos.write(Base64.getEncoder().encode((serverPubkey.getEncoded())));
            fos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        announcementFile.deleteOnExit();
    }

    public static String urlDecode(String encoded) {
        return encoded.replace(".","+").replace("_","/").replace("-","=");
    }
}
