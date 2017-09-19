package crypt.ssl.connection;

import java.io.InputStream;
import java.io.OutputStream;

public class MessageStream {

    private final InputStream in;
    private final OutputStream out;

    public MessageStream(InputStream in, OutputStream out) {
        this.in = in;
        this.out = out;
    }
}
