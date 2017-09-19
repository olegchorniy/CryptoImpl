package crypt.ssl.messages.handshake;

import crypt.ssl.messages.TlsMessage;
import crypt.ssl.messages.VarLength;
import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@VarLength(3)
@ToString
public abstract class HandshakeMessage implements TlsMessage {

    private HandshakeType type;

    public int getLength() {
        throw new UnsupportedOperationException();
    }
}
