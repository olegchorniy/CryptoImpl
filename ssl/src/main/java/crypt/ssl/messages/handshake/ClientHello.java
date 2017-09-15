package crypt.ssl.messages.handshake;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ClientHello extends HandshakeMessage {

    private ProtocolVersion clientVersion;
    private RandomValue random;
    private SessionId sessionId;

    @VarLength(2)
    private List<CipherSuite> cipherSuites;

    @VarLength(1)
    private List<CompressionMethod> compressionMethods;

    private Extensions extensions;

    public ClientHello() {
        super(HandshakeType.CLIENT_HELLO);
    }

    public ClientHello(ProtocolVersion clientVersion,
                       RandomValue random,
                       SessionId sessionId,
                       List<CipherSuite> cipherSuites,
                       List<CompressionMethod> compressionMethods,
                       Extensions extensions) {
        super(HandshakeType.CLIENT_HELLO);

        this.clientVersion = clientVersion;
        this.random = random;
        this.sessionId = sessionId;
        this.cipherSuites = cipherSuites;
        this.compressionMethods = compressionMethods;
        this.extensions = extensions;
    }
}
