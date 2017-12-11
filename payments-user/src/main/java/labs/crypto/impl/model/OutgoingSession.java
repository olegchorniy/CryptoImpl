package labs.crypto.impl.model;

import crypt.payments.registration.User;
import lombok.Data;

import java.util.UUID;

@Data
public class OutgoingSession {

    private final UUID sessionId;
    private final User recipient;
    private final byte[][] paywords;

    private volatile int lastPaymentIndex;

    public OutgoingSession(UUID sessionId, User recipient, byte[][] paywords) {
        this.sessionId = sessionId;
        this.recipient = recipient;
        this.paywords = paywords;
    }
}
