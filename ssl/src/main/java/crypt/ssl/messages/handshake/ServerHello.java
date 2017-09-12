package crypt.ssl.messages.handshake;

import crypt.ssl.messages.*;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class ServerHello extends HandshakeMessage {

    private ProtocolVersion serverVersion;
    private RandomValue random;
    private SessionId sessionId;
    private CipherSuite cipherSuite;
    private CompressionMethod compressionMethod;
    private List<Extension> extensions;

    public ServerHello() {
        super(HandshakeType.SERVER_HELLO);
    }

    public ServerHello(ProtocolVersion serverVersion,
                       RandomValue random,
                       SessionId sessionId,
                       CipherSuite cipherSuite,
                       CompressionMethod compressionMethod,
                       List<Extension> extensions) {

        super(HandshakeType.SERVER_HELLO);

        this.serverVersion = serverVersion;
        this.random = random;
        this.sessionId = sessionId;
        this.cipherSuite = cipherSuite;
        this.compressionMethod = compressionMethod;
        this.extensions = extensions;
    }
}
