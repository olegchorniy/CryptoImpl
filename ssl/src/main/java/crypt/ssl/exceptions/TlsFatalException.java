package crypt.ssl.exceptions;

import crypt.ssl.messages.alert.AlertDescription;

public class TlsFatalException extends TlsException {

    private final AlertDescription description;

    public TlsFatalException(AlertDescription description) {
        this.description = description;
    }

    public AlertDescription getDescription() {
        return description;
    }
}
