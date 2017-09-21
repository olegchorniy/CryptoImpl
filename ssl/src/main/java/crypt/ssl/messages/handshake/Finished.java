package crypt.ssl.messages.handshake;

import lombok.Getter;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
public class Finished extends HandshakeMessage {

    private ByteBuffer verifyData;

    public Finished() {
        super(HandshakeType.FINISHED);
    }

    public Finished(ByteBuffer verifyData) {
        super(HandshakeType.FINISHED);
        this.verifyData = verifyData;
    }
}
