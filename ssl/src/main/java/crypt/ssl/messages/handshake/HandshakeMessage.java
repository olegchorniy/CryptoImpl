package crypt.ssl.messages.handshake;

import crypt.ssl.messages.TlsMessage;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public abstract class HandshakeMessage implements TlsMessage {

    private HandshakeType type;

    public abstract int getLength();
}
