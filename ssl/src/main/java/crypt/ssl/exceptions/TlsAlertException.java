package crypt.ssl.exceptions;

import crypt.ssl.messages.alert.AlertDescription;
import crypt.ssl.messages.alert.AlertLevel;

public abstract class TlsAlertException extends TlsException {

    private final AlertLevel level;
    private final AlertDescription description;

    protected TlsAlertException(AlertLevel level, AlertDescription description) {
        this.level = level;
        this.description = description;
    }

    public AlertLevel getLevel() {
        return level;
    }

    public AlertDescription getDescription() {
        return description;
    }
}
