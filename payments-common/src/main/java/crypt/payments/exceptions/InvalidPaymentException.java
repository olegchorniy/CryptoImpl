package crypt.payments.exceptions;

import crypt.payments.payword.Payment;
import crypt.payments.utils.HexUtils;

import java.util.UUID;

public class InvalidPaymentException extends RuntimeException {

    public InvalidPaymentException(byte[] root, Payment payment) {
        super("Invalid payment: root =" + HexUtils.toHex(root) + ", payment = " + payment);
    }

    public InvalidPaymentException(UUID sessionId, Payment lastPayment, Payment nextPayment) {
        super("Invalid payment: sessionId=" + sessionId + ", lastPayment=" + lastPayment + ", nextPayment = " + nextPayment);
    }
}
