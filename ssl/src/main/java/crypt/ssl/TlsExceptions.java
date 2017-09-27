package crypt.ssl;

import crypt.ssl.exceptions.TlsAlertException;
import crypt.ssl.messages.alert.AlertDescription;

import java.io.EOFException;

public abstract class TlsExceptions {

    private TlsExceptions() {
    }

    public static TlsAlertException decryptError() {
        return TlsAlertException.fatal(AlertDescription.DECRYPT_ERROR);
    }

    public static TlsAlertException badMac() {
        return TlsAlertException.fatal(AlertDescription.BAD_RECORD_MAC);
    }

    public static TlsAlertException decodeError() {
        return TlsAlertException.fatal(AlertDescription.DECODE_ERROR);
    }

    public static EOFException eofException(String message) {
        return new EOFException(message);
    }

    public static EOFException eofException() {
        return eofException("Unexpected EOF encountered.");
    }
}
