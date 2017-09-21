package crypt.ssl.messages.handshake;

import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class ServerKeyExchange extends HandshakeMessage {

    private ByteBuffer data;

    public ServerKeyExchange() {
        super(HandshakeType.SERVER_KEY_EXCHANGE);
    }

    public ServerKeyExchange(ByteBuffer data) {
        super(HandshakeType.SERVER_KEY_EXCHANGE);
        this.data = data;
    }
}
