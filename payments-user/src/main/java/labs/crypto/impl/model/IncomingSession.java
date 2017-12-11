package labs.crypto.impl.model;

import crypt.payments.payword.Commitment;
import crypt.payments.payword.Payment;
import lombok.Data;

import java.util.UUID;

@Data
public class IncomingSession {

    private final UUID sessionId;
    private final Commitment commitment;

    private volatile Payment lastPayment;
}
