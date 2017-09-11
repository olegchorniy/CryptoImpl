package crypt.ssl.connection;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class SecureConnection implements Connection {

    private Socket socket;

    @Override
    public void connect(InetSocketAddress address) throws IOException {

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
