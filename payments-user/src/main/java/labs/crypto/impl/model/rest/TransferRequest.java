package labs.crypto.impl.model.rest;

import crypt.payments.payword.Payment;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TransferRequest {

    private UUID sessionId;
    private Payment payment;
}
