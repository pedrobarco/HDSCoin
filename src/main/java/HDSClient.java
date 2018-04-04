import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

public class HDSClient {
	public static String server;
	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		System.out.println("----------------------------");
		System.out.println("|     HDS Coin Client      |");
		System.out.println("----------------------------");
		System.out.print("Server address?\n> ");
		server = scanner.nextLine();
		if (!server.startsWith("http://")) {
			server = "http://"+server;
		}
		// TODO: Ping server, ask again if unavailable
		System.out.println("Commands:");
		System.out.println("generate <key name> 											- Generates a public and private key");
		System.out.println("register <path to public key file> <path to private key file> 	- Registers account on HDS with public key");
		boolean running = true;

		while(running){
			System.out.print("> ");
			String[] cmd = scanner.nextLine().split(" ");
			switch(cmd[0]){
				case "generate":
					if (cmd.length != 2) {
						System.out.println("Command 'generate' takes 1 argument: key name");
						break;
					}
					generate(cmd[1]);
					System.out.println("Generated keypair "+cmd[1]+".pub and "+cmd[1]+".priv!");
					break;

				case "register":
					if (cmd.length != 3) {
						System.out.println("Command 'register' takes 2 arguments: path to public key file, path to private key file");
						break;
					}
					register(cmd[1], cmd[2]);
					System.out.println("Registered!");
					break;

				case "exit":
					System.out.println("Application Closed");
					running = false;
					break;

				default:
					System.out.println("Command not recognized!");
					break;
			}
		}
		scanner.close();
	}

	public static void register(String pubkeyFile, String privkeyFile) {
		PrivateKey privateKey = null;
		PublicKey publicKey = null;
		try {
			byte[] privkeyBytes = Files.readAllBytes(Paths.get(privkeyFile));
			PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privkeyBytes);
			KeyFactory factory = KeyFactory.getInstance("EC", "SunEC");
			privateKey = factory.generatePrivate(privSpec);

			byte[] pubkeyBytes = Files.readAllBytes(Paths.get(pubkeyFile));
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubkeyBytes);
			publicKey = factory.generatePublic(pubSpec);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}
		String publicKeyString = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
		System.out.println("Public key: " + publicKeyString);
		String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
		System.out.println("Timestamp: " + timestamp);
		String sig = new String(Base64.getEncoder().encode(createSignatureEC(timestamp.getBytes(), privateKey)));
		System.out.println("Sig: " + sig);

		try {
			HttpResponse<JsonNode> jsonResponse = Unirest.post(server + "/hds/") // TODO: Put right path
					.header("accept", "application/json")
					.field("key", publicKeyString)
					.field("timestamp", timestamp)
					.field("sig", sig)
					.asJson();

			System.out.println(jsonResponse.toString());
		} catch (UnirestException e) {
			e.printStackTrace();
		}
	}

	public static void generate(String keyname){
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

		try {
			FileOutputStream fos = new FileOutputStream(keyname+".pub");
			fos.write(pubkey.getEncoded());
			fos.close();

			fos = new FileOutputStream(keyname+".priv");
			fos.write(privkey.getEncoded());
			fos.close();
		} catch (java.io.IOException e) {
			e.printStackTrace();
		}
	}

	public static byte[] createSignatureEC(byte[] data, PrivateKey priv){
		try {
			Signature s = Signature.getInstance("SHA256withECDSA");
			s.initSign(priv);
			s.update(data);
			return s.sign();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
