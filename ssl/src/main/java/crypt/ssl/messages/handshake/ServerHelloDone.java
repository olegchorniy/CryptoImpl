package crypt.ssl.messages.handshake;

public class ServerHelloDone extends HandshakeMessage {

    public static final ServerHelloDone INSTANCE = new ServerHelloDone();

    private ServerHelloDone() {
        super(HandshakeType.SERVER_HELLO_DONE);
    }
}
