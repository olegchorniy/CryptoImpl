package crypt.ssl.connection;

import crypt.ssl.encoding.TlsDecoder;
import crypt.ssl.messages.ApplicationData;
import crypt.ssl.messages.ContentType;
import crypt.ssl.messages.TlsMessage;
import crypt.ssl.messages.TlsRecord;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.handshake.HandshakeMessage;
import crypt.ssl.messages.handshake.HandshakeType;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import static crypt.ssl.encoding.TlsDecoder.TLS_ALERT_LENGTH;
import static crypt.ssl.encoding.TlsDecoder.TLS_HANDSHAKE_HEADER_LENGTH;

public class MessageStream {

    private final InputStream in;
    private final OutputStream out;

    private final Buffer messagesBuffer = new Buffer();
    private ContentType lastContentType = null;

    public MessageStream(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }

    public TlsMessage readMessage() throws IOException {
        while (true) {
            TlsMessage message = tryReadMessage();

            if (message != null) {
                // there was enough data in the buffer to deserialize a message
                return message;
            }

            // try to read more data from the stream and
            // in case of success go to the next iteration
            if (!readRecordIntoBuffer()) {

                // there is no data in the stream anymore
                return null;
            }
        }
    }

    private TlsMessage tryReadMessage() {
        if (this.lastContentType == null) {
            return null;
        }

        TlsMessage message = tryReadMessageOfType(this.lastContentType);
        if (message == null) {
            return null;
        }

        if (this.messagesBuffer.isEmpty()) {
            // we are ready to receive messages of the new content type,
            // probably the same as the last one
            this.lastContentType = null;
        }

        return message;
    }

    private TlsMessage tryReadMessageOfType(ContentType type) {

        switch (type) {
            case ALERT:
                return tryReadAlert();

            case HANDSHAKE:
                return tryReadHandshake();

            case APPLICATION_DATA:
                //TODO: hmmmm....
                return null;

            case CHANGE_CIPHER_SPEC:
                return null;
        }

        // impossible, as the type cannot be null here
        return null;
    }

    private Alert tryReadAlert() {
        if (this.messagesBuffer.available() >= TLS_ALERT_LENGTH) {
            byte[] alertBody = this.messagesBuffer.getBytes(TLS_ALERT_LENGTH);

            return TlsDecoder.readAlert(ByteBuffer.wrap(alertBody));
        }

        return null;
    }

    private HandshakeMessage tryReadHandshake() {
        int available = this.messagesBuffer.available();

        if (available < TLS_HANDSHAKE_HEADER_LENGTH) {
            return null;
        }

        ByteBuffer header = ByteBuffer.wrap(this.messagesBuffer.peekBytes(TLS_HANDSHAKE_HEADER_LENGTH));

        HandshakeType type = IO.readEnum(header, HandshakeType.class);
        int handshakeLength = IO.readInt24(header);

        if (available < TLS_HANDSHAKE_HEADER_LENGTH + handshakeLength) {
            return null;
        }

        // we've already read it from the buffer
        this.messagesBuffer.skip(TLS_HANDSHAKE_HEADER_LENGTH);

        ByteBuffer body = ByteBuffer.wrap(this.messagesBuffer.getBytes(handshakeLength));

        return TlsDecoder.readHandshakeOfType(type, body);
    }

    private ApplicationData tryReadApplicationData() {
        int available = this.messagesBuffer.available();

        if (available < TLS_HANDSHAKE_HEADER_LENGTH) {
            return null;
        }

        return null;
    }

    private boolean readRecordIntoBuffer() throws IOException {
        TlsRecord record = TlsDecoder.readRecord(in);
        if (record == null) {
            return false;
        }

        ContentType contentType = record.getType();
        byte[] recordBody = record.getRecordBody();

        checkContentType(contentType);

        //TODO: decrypt data here, when encryption is implemented

        this.messagesBuffer.putBytes(recordBody);
        this.lastContentType = contentType;

        return true;
    }

    private void checkContentType(ContentType contentType) {
        if (this.lastContentType != null && this.lastContentType != contentType) {
            throw new IllegalStateException(this.lastContentType + " was expected, but " + contentType + " received");
        }
    }

}
