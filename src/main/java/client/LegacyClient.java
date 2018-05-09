package client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.JsonNode;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

@SuppressWarnings("ALL")
public class LegacyClient {
	public static boolean debug = false;
	public static String server;
	public static PublicKey serverKey;

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);

		System.out.println("----------------------------");
		System.out.println("|     HDS Coin Client      |");
		System.out.println("----------------------------");
		System.out.print("Server address and Server key?\n> ");
		String[] serverinfo = scanner.nextLine().split(" ");
		while (!connect(serverinfo)) {
			serverinfo = scanner.nextLine().split(" ");
		}
		printHelp();
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
					break;

				case "send":
					if (cmd.length != 5) {
						System.out.println("Command 'send' takes 4 arguments: source hash, destination hash, amount to send, path to private key file");
						break;
					}
					send(cmd[1], cmd[2], cmd[3], cmd[4]);
					break;

				case "receive":
					if (cmd.length != 3) {
						System.out.println("Command 'receive' takes 2 arguments: transaction id, path to private key file");
						break;
					}
					receive(cmd[1], cmd[2]);
					break;

				case "check":
					if (cmd.length != 2) {
						System.out.println("Command 'check' takes 1 argument: account hash");
						break;
					}
					check(cmd[1]);
					break;

				case "audit":
					if (cmd.length != 2) {
						System.out.println("Command 'audit' takes 1 argument: account hash");
						break;
					}
					audit(cmd[1]);
					break;

				case "help":
					printHelp();
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

	public static boolean connect(String[] cmd){
		if (cmd.length != 2) {
			System.out.print("Please type in server address and the path to the server's public key (e.g: localhost:8080 server.pub)\n> ");
			return false;
		}
		String address = cmd[0];
		String serverKeyFile = cmd[1];
		if (!address.startsWith("http://")) {
			address = "http://"+address;
		}
		server = address;
		try {
			byte[] pubkeyBytes = Files.readAllBytes(Paths.get(serverKeyFile));
			X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubkeyBytes);
			KeyFactory factory = KeyFactory.getInstance("EC", "SunEC");
			serverKey = factory.generatePublic(pubSpec);
		} catch (NoSuchFileException e){
			System.out.println("[ERROR] Couldn't find file: " + serverKeyFile);
			return false;
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
			return false;
		}
		if (!ping(server)) {
			System.out.print("[ERROR] Server not responding, type server address again\n> ");
			return false;
		}
		return true;
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
		} catch (NoSuchFileException e){
			System.out.println("[ERROR] Couldn't find file: " + privkeyFile + " or " + pubkeyFile);
			return;
		} catch (IOException e) {
			e.printStackTrace();
			return;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
			return;
		}

		String publicKeyString = new String(Base64.getEncoder().encode(publicKey.getEncoded()));
		String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());

		Signature s = null;
		byte[] sig = null;
		try {
			s = createSignature(privateKey);
			s.update(timestamp.getBytes());
			sig = s.sign();
		} catch (InvalidKeyException | SignatureException e) {
			System.out.println("[ERROR] " + e.getMessage());
			return;
		}

		String encodedSig = new String(Base64.getEncoder().encode(sig));
		String address = server + "/hds/";
		if (debug) {
			System.out.println("--- Sending ---");
			System.out.println("Address: " + address);
			System.out.println("Public key: " + publicKeyString);
			System.out.println("Timestamp: " + timestamp);
			System.out.println("Sig: " + encodedSig);
			System.out.println("---------------");
		}

		try {
			HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
					.header("accept", "application/json")
					.field("key", publicKeyString)
					.field("timestamp", timestamp)
					.field("sig", encodedSig)
					.asJson();

			if (debug) {
				System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
			}

			if (!checkServerSignature(jsonResponse.getBody(), timestamp)) {
				System.out.println("[ERROR] Could not verify the server's signature");
				return;
			}

			if (jsonResponse.getStatus() == 400){
				System.out.println("[ERROR] " + jsonResponse.getBody().getObject().get("message"));
				return;
			}
			else if (jsonResponse.getStatus() == 201) {
				System.out.println("Registered successfully! Your hash: " + jsonResponse.getBody().getObject().get("keyHash"));
			}
			else {
				System.out.println("[ERROR] Unexpected status code: " + jsonResponse.getStatus());
			}
		} catch (UnirestException e) {
			e.printStackTrace();
		}
	}

	public static void send(String source, String dest, String amount, String privkeyFile){
		PrivateKey privateKey = null;
		try {
			byte[] privkeyBytes = Files.readAllBytes(Paths.get(privkeyFile));
			PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privkeyBytes);
			KeyFactory factory = KeyFactory.getInstance("EC", "SunEC");
			privateKey = factory.generatePrivate(privSpec);
		} catch (NoSuchFileException e){
			System.out.println("[ERROR] Couldn't find file: " + privkeyFile);
			return;
		} catch (IOException e) {
			e.printStackTrace();
			return;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
			return;
		}

		String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());

		Signature s = null;
		byte[] sig = null;
		try {
			s = createSignature(privateKey);
			s.update(source.getBytes());
			s.update(dest.getBytes());
			s.update(BigInteger.valueOf(Integer.parseInt(amount)).toByteArray());
			s.update(timestamp.getBytes());
			sig = s.sign();
		} catch (InvalidKeyException | SignatureException e) {
			System.out.println("[ERROR] " + e.getMessage());
			return;
		}

		String encodedSig = new String(Base64.getEncoder().encode(sig));
		String address = server + "/hds/"+urlEncode(source)+"/send";

		if (debug) {
			System.out.println("--- Sending ---");
			System.out.println("Address: " + address);
			System.out.println("Source hash: " + source);
			System.out.println("Destination hash: " + dest);
			System.out.println("Amount: " + amount);
			System.out.println("Timestamp: " + timestamp);
			System.out.println("Sig: " + encodedSig);
			System.out.println("---------------");
		}

		try {
			HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
					.header("accept", "application/json")
					.field("destKey", dest)
					.field("amount", amount)
					.field("timestamp", timestamp)
					.field("sig", encodedSig)
					.asJson();

			if (debug) {
				System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
			}

			if (!checkServerSignature(jsonResponse.getBody(), timestamp)) {
				System.out.println("[ERROR] Could not verify the server's signature");
				return;
			}

			if (jsonResponse.getStatus() == 400){
				System.out.println("[ERROR] " + jsonResponse.getBody().getObject().get("message"));
				return;
			}
			else if (jsonResponse.getStatus() == 201) {
				System.out.println("Sent successfully! Transaction id: " + jsonResponse.getBody().getObject().get("id"));
			}
			else {
				System.out.println("[ERROR] Unexpected status code: " + jsonResponse.getStatus());
			}
		} catch (UnirestException e) {
			e.printStackTrace();
		}
	}

	public static void receive(String id, String privkeyFile){
		PrivateKey privateKey = null;
		try {
			byte[] privkeyBytes = Files.readAllBytes(Paths.get(privkeyFile));
			PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privkeyBytes);
			KeyFactory factory = KeyFactory.getInstance("EC", "SunEC");
			privateKey = factory.generatePrivate(privSpec);
		} catch (NoSuchFileException e){
			System.out.println("[ERROR] Couldn't find file: " + privkeyFile);
			return;
		} catch (IOException e) {
			e.printStackTrace();
			return;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
			return;
		}

		String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());

		Signature s = null;
		byte[] sig = null;
		try {
			s = createSignature(privateKey);
			s.update(BigInteger.valueOf(Integer.parseInt(id)).toByteArray());
			s.update(timestamp.getBytes());
			sig = s.sign();
		} catch (InvalidKeyException | SignatureException e) {
			System.out.println("[ERROR] " + e.getMessage());
			return;
		}

		String encodedSig = new String(Base64.getEncoder().encode(sig));
		String address = server + "/hds/receive/"+id;

		if (debug) {
			System.out.println("--- Sending ---");
			System.out.println("Address: " + address);
			System.out.println("Transaction ID: " + id);
			System.out.println("Timestamp: " + timestamp);
			System.out.println("Sig: " + encodedSig);
			System.out.println("---------------");
		}

		try {
			HttpResponse<JsonNode> jsonResponse = Unirest.post(address)
					.header("accept", "application/json")
					.field("id", id)
					.field("timestamp", timestamp)
					.field("sig", encodedSig)
					.asJson();

			if (debug) {
				System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
			}

			if (!checkServerSignature(jsonResponse.getBody(), timestamp)) {
				System.out.println("[ERROR] Could not verify the server's signature");
				return;
			}

			if (jsonResponse.getStatus() == 400){
				System.out.println("[ERROR] " + jsonResponse.getBody().getObject().get("message"));
				return;
			}
			else if (jsonResponse.getStatus() == 201) {
				System.out.println("Received successfully! Amount received: " + jsonResponse.getBody().getObject().get("amount"));
			}
			else {
				System.out.println("[ERROR] Unexpected status code: " + jsonResponse.getStatus());
			}
		} catch (UnirestException e) {
			e.printStackTrace();
		}
	}

	public static void check(String keyHash){
		String address = server + "/hds/"+urlEncode(keyHash)+"/check";
		String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
		if (debug) {
			System.out.println("--- Sending ---");
			System.out.println("Address: " + address);
			System.out.println("Account Hash: " + keyHash);
			System.out.println("Timestamp: " + timestamp);
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

			if (!checkServerSignature(jsonResponse.getBody(), timestamp)) {
				System.out.println("[ERROR] Could not verify the server's signature");
				return;
			}

			if (jsonResponse.getStatus() == 400){
				System.out.println("[ERROR] " + jsonResponse.getBody().getObject().get("message"));
				return;
			}
			else if (jsonResponse.getStatus() == 200) {
				System.out.println("Balance: " + jsonResponse.getBody().getObject().get("amount"));
				System.out.println("Pending transactions: ");
				JSONArray array = jsonResponse.getBody().getObject().getJSONArray("pendingTransactions");
				for(int i = 0; i< array.length(); i++){
					System.out.println(prettyPrintPendingTransaction(array.getJSONObject(i)));
				}
			}
			else {
				System.out.println("[ERROR] Unexpected status code: " + jsonResponse.getStatus());
			}
		} catch (UnirestException e) {
			e.printStackTrace();
		}
	}

	public static void audit(String keyHash){
		String address = server + "/hds/"+urlEncode(keyHash)+"/audit";
		String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
		if (debug) {
			System.out.println("--- Sending ---");
			System.out.println("Address: " + address);
			System.out.println("Account Hash: " + keyHash);
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

			if (!checkServerSignature(jsonResponse.getBody(), timestamp)) {
				System.out.println("[ERROR] Could not verify the server's signature");
				return;
			}

			if (jsonResponse.getStatus() == 400){
				System.out.println("[ERROR] " + jsonResponse.getBody().getObject().get("message"));
				return;
			}
			else if (jsonResponse.getStatus() == 200) {
				System.out.println("Transaction list: ");
				JSONArray array = jsonResponse.getBody().getObject().getJSONArray("transactions");
				for(int i = 0; i< array.length(); i++){
					System.out.println(prettyPrintTransaction(array.getJSONObject(i)));
					System.out.println("");
				}
			}
			else {
				System.out.println("[ERROR] Unexpected status code: " + jsonResponse.getStatus());
			}
		} catch (UnirestException e) {
			e.printStackTrace();
		}
	}

	public static boolean ping(String server) {
		if (debug) {
			System.out.println("[DEBUG] Pinging Server");
		}
		try {
			String timestamp = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date());
			HttpResponse<JsonNode> jsonResponse = Unirest.post(server+"/hds/ping")
					.field("timestamp", timestamp)
					.asJson();
			if (debug) {
				System.out.println("[DEBUG] Got " + jsonResponse.getStatus());
				System.out.println(prettyPrintJsonString(jsonResponse.getBody()));
			}
			if (!checkServerSignature(jsonResponse.getBody(), timestamp)) {
				System.out.println("[ERROR] Could not verify the server's signature");
				return false;
			}
			return jsonResponse.getStatus() == 200;
		} catch (UnirestException e) {
			return false;
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

	public static boolean checkServerSignature(JsonNode response, String timestamp){
		byte[] serverSig = null;
		try {
			serverSig = Base64.getDecoder().decode(response.getObject().getString("serverSig"));
		} catch (JSONException e) {
			if (debug) {
				System.out.println("[DEBUG] Couldn't find the serverSig");
			}
			return false;
		}

		try {
			Signature serverSigVerify = verifySignature(serverKey);
			serverSigVerify.update(timestamp.getBytes());
			if (!serverSigVerify.verify(serverSig)){
				if (debug) {
					System.out.println("[DEBUG] Failed to verify the serverSig");
				}
				return false;
			}
		} catch (InvalidKeyException | SignatureException e) {
			if (debug) {
				System.out.println("[DEBUG] Exception while verifying serverSig:");
				System.out.println("[DEBUG] " + e.getMessage());
			}
			return false;
		}
		return true;
	}

	public static Signature createSignature(PrivateKey priv) throws InvalidKeyException {
		Signature s = null;
		try {
			s = Signature.getInstance("SHA256withECDSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		s.initSign(priv);
		return s;
	}

	public static Signature verifySignature(PublicKey pub) throws InvalidKeyException {
		Signature s = null;
		try {
			s = Signature.getInstance("SHA256withECDSA");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		s.initVerify(pub);
		return s;
	}

	public static String keyToString(Key key){
		return new String(Base64.getEncoder().encode(key.getEncoded()));
	}

	private static String urlEncode(String url) {
		return url.replace("+",".").replace("/","_").replace("=","-");
	}

	public static String prettyPrintJsonString(JsonNode jsonNode) {
		try {
			ObjectMapper mapper = new ObjectMapper();
			Object json = mapper.readValue(jsonNode.toString(), Object.class);
			return mapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
		} catch (Exception e) {
			return "Sorry, pretty print didn't work";
		}
	}

	public static String prettyPrintPendingTransaction(JSONObject transaction) {
		String id = Integer.toString(transaction.getInt("id"));
		String amount = Integer.toString(transaction.getInt("amount"));
		String from = transaction.getJSONObject("from").getString("keyHash");
		return "  Transaction " + id + ": " + amount + " coins [FROM: " + from + "]";
	}

	public static String prettyPrintTransaction(JSONObject transaction) {
		String id = Integer.toString(transaction.getInt("id"));
		String amount = Integer.toString(transaction.getInt("amount"));
		String from = transaction.getJSONObject("from").getString("keyHash");
		String to = transaction.getJSONObject("to").getString("keyHash");
		boolean pending = transaction.getBoolean("pending");
		return "Transaction " + id + "\nAmount: " + amount + "\nFrom: " + from + "\nTo: " + to + "\nPending: " + pending;
	}

	public static void printHelp(){
		System.out.println("Commands:");
		System.out.println("generate <key name> - Generates a public and private key");
		System.out.println("register <path to public key file> <path to private key file> - Registers account on HDS with public key");
		System.out.println("send <source hash> <destination hash> <amount> <path to private key> - Sends 'amount' coins from source to destination");
		System.out.println("receive <transaction id> <path to private key> - Confirms reception of a transaction");
		System.out.println("check <account hash> - Checks balance and pending transactions");
		System.out.println("audit <account hash> - Lists all transactions from the account");
	}
}
