package client;

import client.commands.*;
import client.domain.Account;
import client.domain.Server;
import client.domain.Transaction;
import com.mashape.unirest.http.JsonNode;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.stream.Collectors;

import static client.ClientCrypto.generateCertificate;
import static client.ClientCrypto.prettyPrintJsonString;

@SuppressWarnings("Duplicates")
public class Client {
    private static PublicKey publicKey = null;
    private static PrivateKey privateKey = null;

    private static String publicKeyHash = null;

    public static List<Server> servers;

    private static int responses;
    private static Map<String, Integer> errors;
    private static List<Object> validResponses;
    private static List<JsonNode> jsonResponses; // Used to writeback

    private static List<Transaction> transactionList;
    private static Account account;

    private static final Object syncObject = new Object();

    // Verbose debug mode will make ugly threaded prints
    public enum debugMode {NONE, NORMAL, VERBOSE}
    public static debugMode debug = debugMode.NORMAL;

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("----------------------------");
        System.out.println("|     HDS Coin Client      |");
        System.out.println("----------------------------");
        System.out.println("1 - Use existing keystore");
        System.out.println("2 - Generate new keystore");
        String choice = "";
        while(choice.equals("")) {
            System.out.print("> ");
            choice = scanner.nextLine();
            switch (choice) {
                case "1":
                    break;
                case "2":
                    break;
                default:
                    choice = "";
                    System.out.println("Please select 1 or 2");
                    break;
            }
        }

        while (publicKeyHash == null) {
            System.out.print("Keystore file: ");
            String path = scanner.nextLine();
            System.out.print("Keystore password: ");
            String password = scanner.nextLine();
            if (choice.equals("1")) {
                try {
                    LoadKeyStore(path, password);
                } catch (FileNotFoundException e) {
                    System.out.println("Couldn't open file \"" + path + "\"");
                    continue;
                }
                System.out.println("Loaded key: " + publicKeyHash);
            } else {
                GenerateKeyStore(path, password);
                System.out.println("Generated key: " + publicKeyHash);
            }
        }

        fetchServers();

        choice = "";
        while (!choice.equals("0")) {
            System.out.println("Available operations:");
            System.out.println("1 - Register");
            System.out.println("2 - Send Coins");
            System.out.println("3 - Receive Transaction");
            System.out.println("4 - Check balance/pending transactions");
            System.out.println("5 - Audit");
            System.out.println("0 - Exit");
            System.out.print("> ");
            choice = scanner.nextLine();
            switch (choice){
                case "1":
                    register();
                    break;
                case "2":
                    if (!audit(false)) {
                        break;
                    }
                    System.out.print("Destination: ");
                    String dest = scanner.nextLine();
                    System.out.print("Amount: ");
                    String amount = scanner.nextLine();
                    send(dest, amount);
                    break;
                case "3":
                    if (!audit(false)) {
                        break;
                    }
                    if (!check()) {
                        break;
                    }
                    if (account.getPendingTransactions().isEmpty()){
                        break;
                    }
                    System.out.print("Transaction ID: ");
                    String id = scanner.nextLine();
                    receive(id);
                    break;
                case "4":
                    check();
                    break;
                case "5":
                    audit(true);
                    break;
                case "0":
                    break;
                default:
                    break;
            }
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
            privateKey = (PrivateKey)ks.getKey("private", password.toCharArray());
            publicKey = ks.getCertificate("private").getPublicKey();
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
        digester.update(publicKey.getEncoded());
        publicKeyHash = Base64.getEncoder().encodeToString(digester.digest());
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
        publicKey = pubkey;
        privateKey = privkey;
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }
        digester.update(publicKey.getEncoded());
        publicKeyHash = Base64.getEncoder().encodeToString(digester.digest());
    }

    private static void fetchServers(){
        servers = new ArrayList<>();
        File dir = new File("servers");
        File[] directoryListing = dir.listFiles();
        if (directoryListing != null) {
            for (File file : directoryListing) {
                try {
                    List<String> announcement = Files.readAllLines(file.toPath());
                    byte[] pubkeyBytes = Base64.getDecoder().decode(announcement.get(2));
                    X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubkeyBytes);
                    KeyFactory factory = KeyFactory.getInstance("EC", "SunEC");
                    PublicKey serverKey = factory.generatePublic(pubSpec);
                    servers.add(new Server(announcement.get(0), announcement.get(1), serverKey));
                } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
                    e.printStackTrace();
                }
            }
        }
        // TODO: Ping?
        System.out.println("Connected to " + servers.size() + " servers");
    }

    public static void register(){
        responses = 0;
        errors = new HashMap<>();
        validResponses = new LinkedList<>();
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        String signature = Register.sign(publicKey, timestamp, privateKey);

        if (debug == debugMode.NORMAL) {
            System.out.println("--- Sending ---");
            System.out.println("Public key: " + publicKeyHash);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("Sig: " + signature);
            System.out.println("---------------");
        }

        for (Server server:servers){
            Thread t = new Thread(new Register(server, publicKey, timestamp, signature));
            t.start();
        }

        synchronized(syncObject) {
            try {
                syncObject.wait();
            } catch (InterruptedException e) {
                System.out.println("[DEBUG] Thread interrupted");
            }
        }
        if (debug == debugMode.NORMAL) {
            System.out.println("[DEBUG] Received majority responses");

            if (validResponses.isEmpty()) {
                for (String error:errors.keySet()){
                    System.out.println("[DEBUG] " + errors.get(error) + " servers returned error:\n[DEBUG] " + error);
                }
            }
        }

        String response = "[ERROR] Couldn't get any response. This shouldn't happen.";
        long max = 0;
        Map<String, Long> counts =
                validResponses.stream().collect(Collectors.groupingBy(e -> (String)e, Collectors.counting()));
        for (String r:counts.keySet()){
            if (counts.get(r) > max){
                max = counts.get(r);
                response = r;
            }
        }
        for (String e:errors.keySet()){
            if (errors.get(e) >= max){
                max = errors.get(e);
                response = "[ERROR] " + e;
            }
        }

        System.out.println(response);
    }

    public static synchronized void callbackRegister(Server server, String response){
        responses = responses+1;
        validResponses.add(response);
        if (debug == debugMode.VERBOSE) {
            System.out.println("[DEBUG] Received " + responses + " responses so far");
        }
        // TODO: determine how many are needed for majority
        if (responses >= 2){
            synchronized (syncObject) {
                syncObject.notify();
            }
        }
    }

    public static void send(String dest, String amount){
        responses = 0;
        errors = new HashMap<>();
        validResponses = new LinkedList<>();
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        String previousTransaction = "000000";
        if (transactionList != null && !transactionList.isEmpty()){
            previousTransaction = transactionList.get(transactionList.size()-1).getTransactionHash();
        }
        String signature = Send.sign(publicKeyHash, dest, amount, previousTransaction, timestamp, privateKey);

        if (debug == debugMode.NORMAL) {
            System.out.println("--- Sending ---");
            System.out.println("Source hash: " + publicKeyHash);
            System.out.println("Destination hash: " + dest);
            System.out.println("Amount: " + amount);
            System.out.println("Previous transaction: " + previousTransaction);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("Sig: " + signature);
            System.out.println("---------------");
        }

        for (Server server:servers){
            Thread t = new Thread(new Send(server, publicKeyHash, dest, amount, previousTransaction, timestamp, signature));
            t.start();
        }

        synchronized(syncObject) {
            try {
                syncObject.wait();
            } catch (InterruptedException e) {
                System.out.println("[DEBUG] Thread interrupted");
            }
        }
        if (debug == debugMode.NORMAL) {
            System.out.println("[DEBUG] Received majority responses");

            if (validResponses.isEmpty()) {
                for (String error:errors.keySet()){
                    System.out.println("[DEBUG] " + errors.get(error) + " servers returned error:\n[DEBUG] " + error);
                }
            }
        }

        String response = "[ERROR] Couldn't get any response. This shouldn't happen.";
        long max = 0;
        Map<String, Long> counts =
                validResponses.stream().collect(Collectors.groupingBy(e -> (String)e, Collectors.counting()));
        for (String r:counts.keySet()){
            if (counts.get(r) > max){
                max = counts.get(r);
                response = r;
            }
        }
        for (String e:errors.keySet()){
            if (errors.get(e) >= max){
                max = errors.get(e);
                response = "[ERROR] " + e;
            }
        }

        System.out.println(response);
    }

    public static synchronized void callbackSend(Server server, String response){
        responses = responses+1;
        validResponses.add(response);
        if (debug == debugMode.VERBOSE) {
            System.out.println("[DEBUG] Received " + responses + " responses so far");
        }
        // TODO: determine how many are needed for majority
        if (responses >= 2){
            synchronized (syncObject) {
                syncObject.notify();
            }
        }
    }

    public static void receive(String transactionID){
        responses = 0;
        errors = new HashMap<>();
        validResponses = new LinkedList<>();
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        String transactionSig = account.getPendingTransactions().get(transactionID).getSignature();
        if (transactionSig == null) {
            System.out.println("[ERROR] No such transaction ID");
            return;
        }
        String previousTransaction = "000000";
        if (transactionList != null && !transactionList.isEmpty()){
            previousTransaction = transactionList.get(transactionList.size()-1).getTransactionHash();
        }
        String signature = Receive.sign(transactionID, transactionSig, previousTransaction, timestamp, privateKey);

        if (debug == debugMode.NORMAL) {
            System.out.println("--- Sending ---");
            System.out.println("Transaction ID: " + transactionID);
            System.out.println("Transaction Sig: " + transactionSig);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("Sig: " + signature);
            System.out.println("---------------");
        }

        for (Server server:servers){
            Thread t = new Thread(new Receive(server, transactionID, transactionSig, previousTransaction, timestamp, signature));
            t.start();
        }

        synchronized(syncObject) {
            try {
                syncObject.wait();
            } catch (InterruptedException e) {
                System.out.println("[DEBUG] Thread interrupted");
            }
        }
        if (debug == debugMode.NORMAL) {
            System.out.println("[DEBUG] Received majority responses");

            if (validResponses.isEmpty()) {
                for (String error:errors.keySet()){
                    System.out.println("[DEBUG] " + errors.get(error) + " servers returned error:\n[DEBUG] " + error);
                }
            }
        }

        String response = "[ERROR] Couldn't get any response. This shouldn't happen.";
        long max = 0;
        Map<String, Long> counts =
                validResponses.stream().collect(Collectors.groupingBy(e -> (String)e, Collectors.counting()));
        for (String r:counts.keySet()){
            if (counts.get(r) > max){
                max = counts.get(r);
                response = r;
            }
        }
        for (String e:errors.keySet()){
            if (errors.get(e) >= max){
                max = errors.get(e);
                response = "[ERROR] " + e;
            }
        }

        System.out.println(response);
    }

    public static synchronized void callbackReceive(Server server, String response){
        responses = responses+1;
        validResponses.add(response);
        if (debug == debugMode.VERBOSE) {
            System.out.println("[DEBUG] Received " + responses + " responses so far");
        }
        // TODO: determine how many are needed for majority
        if (responses >= 2){
            synchronized (syncObject) {
                syncObject.notify();
            }
        }
    }

    public static boolean check(){
        responses = 0;
        errors = new HashMap<>();
        validResponses = new LinkedList<>();
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        if (debug == debugMode.NORMAL) {
            System.out.println("--- Sending ---");
            System.out.println("Account Hash: " + publicKeyHash);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("---------------");
        }

        for (Server server:servers){
            Thread t = new Thread(new Check(server, publicKeyHash,timestamp));
            t.start();
        }

        synchronized(syncObject) {
            try {
                syncObject.wait();
            } catch (InterruptedException e) {
                System.out.println("[DEBUG] Thread interrupted");
            }
        }
        if (debug == debugMode.NORMAL) {
            System.out.println("[DEBUG] Received majority responses");
        }
        if (validResponses.isEmpty()) {
            for (String error:errors.keySet()){
                System.out.println(errors.get(error) + " servers returned error:\n" + error);
            }
            return false;
        }

        long max = 0;
        Map<Account, Long> counts =
                validResponses.stream().collect(Collectors.groupingBy(e -> (Account)e, Collectors.counting()));
        for (Account a:counts.keySet()){
            if (counts.get(a) > max){
                max = counts.get(a);
                account = a;
            }
        }

        System.out.println("Balance for " + publicKeyHash + ": " + account.getBalance());
        if (account.getPendingTransactions() == null || account.getPendingTransactions().isEmpty()) {
            System.out.println("No pending transactions found");
        } else {
            System.out.println("Pending transaction list: ");
            for (Transaction t : account.getPendingTransactions().values()) {
                System.out.println();
                System.out.println(t.toString());
            }
        }
        return true;
    }

    public static synchronized void callbackCheck(Server server, Account response){
        responses = responses+1;
        validResponses.add(response);
        if (debug == debugMode.VERBOSE) {
            System.out.println("[DEBUG] Received " + responses + " responses so far");
        }
        // TODO: determine how many are needed for majority
        if (responses >= 2){
            synchronized (syncObject) {
                syncObject.notify();
            }
        }
    }

    public static boolean audit(boolean print){
        responses = 0;
        errors = new HashMap<>();
        validResponses = new LinkedList<>();
        jsonResponses = new LinkedList<>();
        String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        if (debug == debugMode.NORMAL) {
            System.out.println("--- Sending ---");
            System.out.println("Account Hash: " + publicKeyHash);
            System.out.println("Timestamp: " + timestamp);
            System.out.println("---------------");
        }

        for (Server server:servers){
            Thread t = new Thread(new Audit(server, publicKeyHash,timestamp, publicKey));
            t.start();
        }

        synchronized(syncObject) {
            try {
                syncObject.wait();
            } catch (InterruptedException e) {
                System.out.println("[DEBUG] Thread interrupted");
            }
        }
        if (debug == debugMode.NORMAL) {
            System.out.println("[DEBUG] Received majority responses");
        }
        if (validResponses.isEmpty()) {
            for (String error:errors.keySet()){
                System.out.println(errors.get(error) + " servers returned error:\n" + error);
            }
            return false;
        }
        int maxOps = 0;
        List<Transaction> chosenList = null;
        JsonNode writebackValue = null;
        for (Object response:validResponses){
            int index = validResponses.indexOf(response);
            List<Transaction> l = (List<Transaction>) response;
            if (l.size() > maxOps) {
                maxOps = l.size();
                chosenList = l;
                writebackValue = jsonResponses.get(index);
            }
        }

        if (debug == debugMode.NORMAL) {
            System.out.println("[DEBUG] Writing back");
        }
        // -------------- Writeback --------------------
        timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
        responses = 0;
        errors = new HashMap<>();
        validResponses = new LinkedList<>();
        for (Server server:servers){
            Thread t = new Thread(new Writeback(server, publicKeyHash, writebackValue, timestamp));
            t.start();
        }

        synchronized(syncObject) {
            try {
                syncObject.wait();
            } catch (InterruptedException e) {
                System.out.println("[DEBUG] Thread interrupted");
            }
        }
        if (debug == debugMode.NORMAL) {
            System.out.println("[DEBUG] Finishing writeback");
        }
        //----------- End of Writeback -----------------
        if (print) {
            if (chosenList == null) {
                System.out.println("No transactions found for " + publicKeyHash);
            } else {
                System.out.println("Transaction list for " + publicKeyHash);
                for (Transaction t : chosenList) {
                    System.out.println();
                    System.out.println(t.toString());
                }
            }
        }

        transactionList = chosenList;
        return true;
    }

    public static synchronized void callbackAudit(Server server, List<Transaction> response, JsonNode json){
        responses = responses+1;
        validResponses.add(response);
        jsonResponses.add(json);
        if (debug == debugMode.VERBOSE) {
            System.out.println("[DEBUG] Added transaction list of size " + response.size());
            System.out.println("[DEBUG] Received " + responses + " responses so far");
        }
        // TODO: determine how many are needed for majority
        if (responses >= 2){
            synchronized (syncObject) {
                syncObject.notify();
            }
        }
    }

    public static synchronized void callbackWriteback(Server server, String response){
        responses = responses+1;
        if (debug == debugMode.VERBOSE) {
            System.out.println("[DEBUG] Received " + responses + " responses for writeback so far");
        }
        // TODO: determine how many are needed for majority
        if (responses >= 2){
            synchronized (syncObject) {
                syncObject.notify();
            }
        }
    }

    public static synchronized void callbackError(Server server, String response){
        responses = responses+1;
        if (errors.containsKey(response)){
            errors.put(response, errors.get(response)+1);
        } else {
            errors.put(response, 1);
        }

        if (debug == debugMode.VERBOSE) {
            System.out.println("[DEBUG] Got error: " + response);
            System.out.println("[DEBUG] Received " + responses + " responses so far");
        }
        // TODO: determine how many are needed for majority
        if (responses >= 2){
            synchronized (syncObject) {
                syncObject.notify();
            }
        }
    }
}
