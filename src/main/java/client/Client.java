package client;

import client.commands.*;
import client.domain.Server;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import static client.ClientCrypto.generateCertificate;

@SuppressWarnings("Duplicates")
public class Client {
    private enum Command {REGISTER, SEND, RECEIVE, CHECK, AUDIT}
    private static PublicKey publicKey = null;
    private static PrivateKey privateKey = null;

    private static String publicKeyHash = null;

    public static List<Server> servers;

    private static List<Integer> responses;
    private static final Object syncObject = new Object();

    public static boolean debug = false;

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
                    runCommand(Command.REGISTER);
                    break;
                case "2":
                    System.out.print("Destination: ");
                    String dest = scanner.nextLine();
                    System.out.print("Amount: ");
                    String amount = scanner.nextLine();
                    runCommand(Command.SEND, dest, amount);
                    break;
                case "3":
                    runCommand(Command.CHECK);
                    System.out.print("Transaction ID: ");
                    String id = scanner.nextLine();
                    // TODO: Automatically get signature (store transactions)
                    System.out.print("Signature: ");
                    String signature = scanner.nextLine();
                    if (!org.apache.commons.codec.binary.Base64.isBase64(signature)){
                        System.out.println("Signature is not valid Base64");
                        break;
                    }
                    runCommand(Command.RECEIVE, id, signature);
                    break;
                case "4":
                    runCommand(Command.CHECK);
                    break;
                case "5":
                    runCommand(Command.AUDIT);
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

    private static void runCommand(Command c, String... args){
        responses = new LinkedList<>();
        for (Server server:servers){
            Thread t;
            switch (c){
                case REGISTER:
                    t = new Thread(new Register(server, publicKey, privateKey));
                    t.start();
                    break;
                case SEND:
                    t = new Thread(new Send(server, publicKeyHash, args[0], args[1], privateKey));
                    t.start();
                    break;
                case RECEIVE:
                    t = new Thread(new Receive(server, args[0], args[1], privateKey));
                    t.start();
                    break;
                case CHECK:
                    t = new Thread(new Check(server, publicKeyHash));
                    t.start();
                    break;
                case AUDIT:
                    t = new Thread(new Audit(server, publicKeyHash));
                    t.start();
                    break;
            }
        }
        synchronized(syncObject) {
            try {
                syncObject.wait();
            } catch (InterruptedException e) {
                System.out.println("[DEBUG] Thread interrupted");
            }
        }
        System.out.println("[DEBUG] Received all responses");
    }

    public static synchronized void callback(int status){
        responses.add(status);
        System.out.println("Received " + responses.size() + " responses so far");
        // TODO: determine how many are needed for majority
            if (responses.size() >= 2){
            synchronized (syncObject) {
                syncObject.notify();
            }
        }
    }
}
