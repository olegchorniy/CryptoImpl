package crypt.ssl.connection;

import crypt.ssl.CipherSuite;
import crypt.ssl.cipher.BlockCipher;
import crypt.ssl.cipher.TlsCipher;
import crypt.ssl.encoding.TlsDecoder;
import crypt.ssl.encoding.TlsEncoder;
import crypt.ssl.messages.ContentType;
import crypt.ssl.messages.ProtocolVersion;
import crypt.ssl.messages.RawMessage;
import crypt.ssl.messages.TlsRecord;
import crypt.ssl.messages.handshake.HandshakeType;
import crypt.ssl.utils.Assert;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

import static crypt.ssl.encoding.TlsDecoder.*;
import static crypt.ssl.messages.ContentType.APPLICATION_DATA;
import static java.lang.Math.min;

//TODO: add flushes here or in the TlsConnection
public class MessageStream {

    public static final int PLAINTEXT_MAX_LENGTH = 1 << 14;
    public static final int COMPRESSED_MAX_LENGTH = PLAINTEXT_MAX_LENGTH + (1 << 10);
    public static final int ENCRYPTED_MAX_LENGTH = COMPRESSED_MAX_LENGTH + (1 << 10);

    private final InputStream in;
    private final OutputStream out;
    private final TlsContext context;

    private TlsCipher readCipher;
    private TlsCipher writeCipher;

    private ProtocolVersion recordVersion;

    private final Buffer messagesBuffer = new Buffer();
    private ContentType lastContentType = null;

    public MessageStream(TlsContext context, InputStream in, OutputStream out) {
        this.context = context;
        this.in = in;
        this.out = out;
    }

    public void setRecordVersion(ProtocolVersion recordVersion) {
        this.recordVersion = recordVersion;
    }

    public void initEncryption(KeyParameters clientParams, KeyParameters serverParameters) {
        CipherSuite suite = this.context.getSecurityParameters().getCipherSuite();

        this.writeCipher = createCipher(suite, clientParams);
        //this.readCipher = createCipher(suite, serverParameters);
    }

    private TlsCipher createCipher(CipherSuite suite, KeyParameters keyParameters) {
        switch (suite.getCipherType()) {
            case BLOCK_CIPHER:
                return new BlockCipher(this.context, keyParameters);
        }

        return null;
    }

    public RawMessage readMessage() throws IOException {
        while (true) {
            RawMessage message = tryReadMessage();

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

    private RawMessage tryReadMessage() {
        if (this.lastContentType == null) {
            // buffer should be empty because we either didn't have previous messages
            // or we should have cleared this field below if the buffer is exhausted
            Assert.assertTrue(this.messagesBuffer.isEmpty(), "Buffer should be empty");

            return null;
        }

        ByteBuffer messageBody = tryReadMessageBody(this.lastContentType);
        if (messageBody == null) {
            // Attempt to read a message from available in the buffer data has failed.
            // We need to read more data from the underlying stream to reconstruct a message.
            return null;
        }

        RawMessage message = new RawMessage(this.lastContentType, messageBody);

        if (this.messagesBuffer.isEmpty()) {
            // we are ready to receive messages of a new content type,
            // probably the same as the last one
            this.lastContentType = null;
        }

        return message;
    }

    private ByteBuffer tryReadMessageBody(ContentType type) {

        //TODO: add check of the message length

        switch (type) {
            case ALERT:
                return tryReadAlert();

            case HANDSHAKE:
                return tryReadHandshake();

            case CHANGE_CIPHER_SPEC:
                return tryReadChangeCipherSpec();

            default:
                Assert.assertEquals(type, APPLICATION_DATA);

                return tryReadApplicationData();
        }
    }

    private ByteBuffer tryReadAlert() {
        if (this.messagesBuffer.available() < TLS_ALERT_LENGTH) {
            return null;
        }

        return this.messagesBuffer.getBytes(TLS_ALERT_LENGTH);
    }

    private ByteBuffer tryReadHandshake() {
        int available = this.messagesBuffer.available();

        if (available < TLS_HANDSHAKE_HEADER_LENGTH) {
            return null;
        }

        ByteBuffer header = this.messagesBuffer.peekBytes(TLS_HANDSHAKE_HEADER_LENGTH);

        HandshakeType type = IO.readEnum(header, HandshakeType.class);
        int handshakeLength = IO.readInt24(header);

        if (available < TLS_HANDSHAKE_HEADER_LENGTH + handshakeLength) {
            return null;
        }

        return this.messagesBuffer.getBytes(TLS_HANDSHAKE_HEADER_LENGTH + handshakeLength);
    }

    private ByteBuffer tryReadApplicationData() {
        if (this.messagesBuffer.isEmpty()) {
            return null;
        }

        return this.messagesBuffer.getBytes();
    }

    private ByteBuffer tryReadChangeCipherSpec() {
        if (this.messagesBuffer.available() < TLS_CHANGE_CIPHER_SPEC_LENGTH) {
            return null;
        }

        return this.messagesBuffer.getBytes(TLS_CHANGE_CIPHER_SPEC_LENGTH);
    }

    private boolean readRecordIntoBuffer() throws IOException {
        TlsRecord record = TlsDecoder.readRecord(in);
        if (record == null) {
            return false;
        }

        ContentType contentType = record.getType();
        byte[] recordBody = record.getRecordBody();

        checkContentType(contentType);

        if (this.readCipher != null) {
            recordBody = this.readCipher.decrypt(recordBody);
        }

        this.messagesBuffer.putBytes(recordBody);
        this.lastContentType = contentType;

        return true;
    }

    private void checkContentType(ContentType contentType) {
        if (this.lastContentType != null && this.lastContentType != contentType) {
            throw new IllegalStateException(this.lastContentType + " was expected, but " + contentType + " received");
        }
    }

    public void writeMessage(ContentType type, ByteBuffer data) throws IOException {
        while (data.hasRemaining()) {
            int recordLength = min(data.remaining(), COMPRESSED_MAX_LENGTH);
            byte[] recordData = IO.readBytes(data, recordLength);

            TlsRecord record = new TlsRecord(type, this.recordVersion, recordData);

            if (this.writeCipher != null) {
                byte[] encryptedContent = this.writeCipher.encrypt(record);
                record.setRecordBody(encryptedContent);
            }

            TlsEncoder.writeRecord(out, record);
        }
    }
}
