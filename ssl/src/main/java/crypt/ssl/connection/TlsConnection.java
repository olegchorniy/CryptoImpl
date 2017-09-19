package crypt.ssl.connection;

import crypt.ssl.messages.ProtocolVersion;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class TlsConnection implements Connection {

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
}
