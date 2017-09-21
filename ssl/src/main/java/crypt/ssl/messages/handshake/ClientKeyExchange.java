package crypt.ssl.messages.handshake;


public class ClientKeyExchange extends HandshakeMessage {

    public ClientKeyExchange() {
        super(HandshakeType.CLIENT_KEY_EXCHANGE);
    }
}
