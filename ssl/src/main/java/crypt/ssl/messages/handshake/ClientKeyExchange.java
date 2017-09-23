package crypt.ssl.messages.handshake;


import lombok.Getter;

@Getter
public class ClientKeyExchange extends HandshakeMessage {

    private byte[] exchangeKeys;

    public ClientKeyExchange(byte[] exchangeKeys) {
        super(HandshakeType.CLIENT_KEY_EXCHANGE);
        this.exchangeKeys = exchangeKeys;
    }
}
