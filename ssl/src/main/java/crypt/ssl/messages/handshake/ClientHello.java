package crypt.ssl.messages.handshake;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class ClientHello extends HandshakeMessage {

    @Override
    public int getLength() {
        return 0;
    }
}
