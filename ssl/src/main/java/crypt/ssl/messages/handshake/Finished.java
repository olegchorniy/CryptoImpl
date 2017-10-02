package crypt.ssl.messages.handshake;

import crypt.ssl.utils.Hex;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Finished extends HandshakeMessage {

    private byte[] verifyData;

    public Finished() {
        super(HandshakeType.FINISHED);
    }

    public Finished(byte[] verifyData) {
        super(HandshakeType.FINISHED);
        this.verifyData = verifyData;
    }

    @Override
    public String toString() {
        return "Finished(" + Hex.toHex(verifyData) + ')';
    }
}
