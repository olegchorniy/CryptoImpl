package crypt.ssl.exceptions;

import java.io.IOException;

public class TlsException extends IOException {

    public TlsException() {
        super();
    }

    public TlsException(String message) {
        super(message);
    }

    public TlsException(String message, Throwable cause) {
        super(message, cause);
    }

    public TlsException(Throwable cause) {
        super(cause);
    }
}
