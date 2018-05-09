package client.domain;

import java.security.PublicKey;

public class Server {
    private String name;
    private String address;
    private PublicKey publicKey;

    public Server(String name, String address, PublicKey publicKey){
        this.address = address;
        this.publicKey = publicKey;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }
}
