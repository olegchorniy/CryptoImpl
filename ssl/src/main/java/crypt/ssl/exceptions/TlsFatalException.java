package crypt.ssl.exceptions;

import crypt.ssl.messages.alert.AlertDescription;

public class TlsFatalException extends TlsException {

    private final AlertDescription description;

    public TlsFatalException(AlertDescription description) {
        super("Fatal alert raised: " + description);
        this.description = description;
    }

    public TlsFatalException(Throwable cause, AlertDescription description) {
        super("Fatal alert raised: " + description, cause);
        this.description = description;
    }

    public AlertDescription getDescription() {
        return description;
    }
}
