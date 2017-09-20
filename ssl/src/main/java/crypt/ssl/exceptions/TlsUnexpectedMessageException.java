package crypt.ssl.exceptions;

import crypt.ssl.messages.alert.AlertDescription;
import crypt.ssl.messages.alert.AlertLevel;

public class TlsUnexpectedMessageException extends TlsAlertException {

    public TlsUnexpectedMessageException() {
        super(AlertLevel.FATAL, AlertDescription.UNEXPECTED_MESSAGE);
    }
}
