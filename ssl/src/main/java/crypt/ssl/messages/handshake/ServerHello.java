package crypt.ssl.messages.handshake;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ServerHello extends HandshakeMessage {

    private ProtocolVersion serverVersion;
    private RandomValue random;
    private SessionId sessionId;
    private CipherSuite cipherSuite;
    private CompressionMethod compressionMethod;
    private Extensions extensions;

    public ServerHello() {
        super(HandshakeType.SERVER_HELLO);
    }

    public ServerHello(ProtocolVersion serverVersion,
                       RandomValue random,
                       SessionId sessionId,
                       CipherSuite cipherSuite,
                       CompressionMethod compressionMethod,
                       Extensions extensions) {

        super(HandshakeType.SERVER_HELLO);

        this.serverVersion = serverVersion;
        this.random = random;
        this.sessionId = sessionId;
        this.cipherSuite = cipherSuite;
        this.compressionMethod = compressionMethod;
        this.extensions = extensions;
    }

    @Override
    public String toString() {
        return "ServerHello(" +
                "\n\tserverVersion: " + serverVersion +
                ",\n\trandom: " + random +
                ",\n\tsessionId: " + sessionId +
                ",\n\tcipherSuite: " + cipherSuite +
                ",\n\tcompressionMethod: " + compressionMethod +
                ",\n\textensions: " + extensions +
                "\n)";
    }
}
