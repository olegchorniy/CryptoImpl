package crypt.ssl.messages.handshake;

import crypt.ssl.messages.TlsMessage;
import crypt.ssl.messages.VarLength;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@VarLength(3)
public abstract class HandshakeMessage implements TlsMessage {

    private HandshakeType type;

    public int getLength() {
        throw new UnsupportedOperationException();
    }
}
