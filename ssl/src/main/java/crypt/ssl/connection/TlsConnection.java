package crypt.ssl.connection;

import crypt.ssl.encoding.TlsEncoder;
import crypt.ssl.exceptions.NoCloseNotifyException;
import crypt.ssl.exceptions.TlsAlertException;
import crypt.ssl.exceptions.TlsUnexpectedMessageException;
import crypt.ssl.messages.*;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.alert.AlertDescription;
import crypt.ssl.messages.alert.AlertLevel;
import crypt.ssl.messages.handshake.HandshakeMessage;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Random;


public class TlsConnection implements Connection {

    // We don't support other TLS versions.
    private final ProtocolVersion version = ProtocolVersion.TLSv12;
    private final Random random = new Random();

    private Socket socket;
    private MessageStream messageStream;

    private ConnectionState state = ConnectionState.NEW;
    private HandshakeState handshakeState = null;

    private final Buffer applicationDateBuffer = new Buffer();

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

        this.state = ConnectionState.HANDSHAKE;
        this.handshakeState = HandshakeState.CLIENT_HELLO_SENT;

        while (this.state != ConnectionState.ESTABLISHED) {
            readAndHandleMessage();
        }
    }

    private void readAndHandleMessage() throws IOException {
        TlsMessage message = this.messageStream.readMessage();
        if (message == null) {
            throw new NoCloseNotifyException();
        }

        try {
            handleMessage(message);
        } catch (TlsAlertException alert) {
            sendAlert(alert.getLevel(), alert.getDescription());
            //TODO: close the connection
        }
    }

    private void handleMessage(TlsMessage message) throws IOException {
        switch (message.getContentType()) {
            case HANDSHAKE:
                handleHandshakeMessage((HandshakeMessage) message);
                break;

            case CHANGE_CIPHER_SPEC:
                handleChangeCipherSpec((ChangeCipherSpec) message);
                break;

            case APPLICATION_DATA:
                handleApplicationData((ApplicationData) message);
                break;

            case ALERT:
                handleAlertMessage((Alert) message);
                break;
        }
    }

    private void handleHandshakeMessage(HandshakeMessage handshakeMessage) throws IOException {
        if (this.state != ConnectionState.HANDSHAKE) {
            // Actually, there is a scenario where handshake message can be received after connection has been established.
            // It a case when server sends a HELLO_REQUEST message to renegotiate connection parameters.
            // But this part of the protocol in not supported in current implementation.
            throw new TlsUnexpectedMessageException();
        }
    }

    private void handleChangeCipherSpec(ChangeCipherSpec changeCipherSpec) throws IOException {
    }

    private void handleApplicationData(ApplicationData applicationData) throws IOException {
    }

    private void handleAlertMessage(Alert alert) throws IOException {
    }

    private void closeInternal() throws IOException {
        sendAlert(AlertLevel.FATAL, AlertDescription.CLOSE_NOTIFY);
    }

    private void sendAlert(AlertLevel level, AlertDescription description) throws IOException {
        Message message = new Message();

        Alert alert = new Alert(level, description);
        TlsEncoder.writeAlert(message, alert);

        this.messageStream.writeMessage(ContentType.ALERT, message.toBuffer());
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

    private enum ConnectionState {
        NEW,
        HANDSHAKE,
        ESTABLISHED,
        CLOSED
    }

    private enum HandshakeState {
        CLIENT_HELLO_SENT

    }

    private static class Message extends ByteArrayOutputStream {

        public ByteBuffer toBuffer() {
            return ByteBuffer.wrap(this.toByteArray());
        }
    }

    private class TlsInputStream extends InputStream {

        @Override
        public int read() throws IOException {
            return 0;
        }
    }
}
