package crypt.ssl;

import crypt.ssl.exceptions.TlsFatalException;
import crypt.ssl.messages.alert.AlertDescription;

import java.io.EOFException;

public abstract class TlsExceptions {

    private TlsExceptions() {
    }

    public static TlsFatalException decryptError() {
        return new TlsFatalException(AlertDescription.DECRYPT_ERROR);
    }

    public static TlsFatalException badMac() {
        return new TlsFatalException(AlertDescription.BAD_RECORD_MAC);
    }

    public static TlsFatalException decodeError() {
        return new TlsFatalException(AlertDescription.DECODE_ERROR);
    }

    public static TlsFatalException recordOverflow() {
        return new TlsFatalException(AlertDescription.RECORD_OVERFLOW);
    }

    public static EOFException eofException(String message) {
        return new EOFException(message);
    }

    public static EOFException eofException() {
        return eofException("Unexpected EOF encountered.");
    }
}
