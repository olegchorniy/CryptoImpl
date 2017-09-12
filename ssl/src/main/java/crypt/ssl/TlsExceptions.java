package crypt.ssl;

import java.io.EOFException;

public abstract class TlsExceptions {

    private TlsExceptions() {
    }

    public static EOFException eofException(String message) {
        return new EOFException(message);
    }

    public static EOFException eofException() {
        return eofException("Unexpected EOF encountered.");
    }
}
