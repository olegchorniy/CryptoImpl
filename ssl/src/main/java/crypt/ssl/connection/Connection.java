package crypt.ssl.connection;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;

public interface Connection extends Closeable {

    default void connect(String host, int port) throws IOException {
        this.connect(new InetSocketAddress(host, port));
    }

    void connect(InetSocketAddress address) throws IOException;

    InputStream getInput() throws IOException;

    OutputStream getOutput() throws IOException;
}
