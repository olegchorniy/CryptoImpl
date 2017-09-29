package crypt.ssl.exceptions;

import crypt.ssl.messages.alert.AlertDescription;

public class TlsUnexpectedMessageException extends TlsFatalException {

    public TlsUnexpectedMessageException() {
        super(AlertDescription.UNEXPECTED_MESSAGE);
    }
}
