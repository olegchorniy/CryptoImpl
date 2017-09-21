package crypt.ssl.messages.handshake;


import lombok.Getter;

import java.nio.ByteBuffer;

@Getter
public class ClientKeyExchange extends HandshakeMessage {

    private ByteBuffer exchangeKeys;

    public ClientKeyExchange(ByteBuffer exchangeKeys) {
        super(HandshakeType.CLIENT_KEY_EXCHANGE);
        this.exchangeKeys = exchangeKeys;
    }
}
