package crypt.ssl.connection;

import crypt.ssl.encoding.TlsEncoder;
import crypt.ssl.messages.ContentType;
import crypt.ssl.messages.ProtocolVersion;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.alert.AlertDescription;
import crypt.ssl.messages.alert.AlertLevel;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Random;

public class TlsConnection implements Connection {

    private final Random random = new Random();

    private Socket socket;
    private MessageStream messageStream;

    // We don't support other TLS versions.
    private final ProtocolVersion version = ProtocolVersion.TLSv12;

    @Override
    public void connect(InetSocketAddress address) throws IOException {
        this.socket = new Socket();
        this.socket.connect(address);

        InputStream in = this.socket.getInputStream();
        OutputStream out = this.socket.getOutputStream();

        this.messageStream = new MessageStream(in, out);
        this.messageStream.setRecordVersion(this.version);

        performHandshake();
    }

    private void performHandshake() throws IOException {

        //sendClientHello();
        //TODO: Hmmm... single loop for all records or separate loop for handshake
    }

    @Override
    public InputStream getInput() throws IOException {
        return null;
    }

    @Override
    public OutputStream getOutput() throws IOException {
        return null;
    }

    @Override
    public void close() throws IOException {

    }

    private void sendAlert(AlertLevel level, AlertDescription description) throws IOException {
        Message message = new Message();

        Alert alert = new Alert(level, description);
        TlsEncoder.writeAlert(message, alert);

        this.messageStream.writeMessage(ContentType.ALERT, message.toBuffer());
    }

    /*private enum ConnectionState {

    }

    private enum HandshakeState {
        NOT_STARTED,
        WAITING_SERVER_HELLO,
        WAITING_SERVER_CERTIFICATE,
        WAITING_SERVER_KEY_EXCHANGE
    }*/

    private static class Message extends ByteArrayOutputStream {

        public ByteBuffer toBuffer() {
            return ByteBuffer.wrap(this.toByteArray());
        }
    }
}
