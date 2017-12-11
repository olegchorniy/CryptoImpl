package crypt.payments;

import crypt.payments.payword.Payment;
import crypt.payments.payword.PaywordUtilities;
import crypt.payments.utils.HashAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PaymentTest {

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void paymentVerificationTest() {
        String hash = HashAlgorithm.SHA1.getValue();

        byte[][] bytes = PaywordUtilities.createPaywordChain(hash, 5);

        Payment first = new Payment(1, bytes[1]);
        Payment second = new Payment(3, bytes[3]);
        Payment third = new Payment(5, bytes[5]);

        assertTrue(PaywordUtilities.verifyPayment(hash, first, second));
        assertTrue(PaywordUtilities.verifyPayment(hash, first, third));
        assertTrue(PaywordUtilities.verifyPayment(hash, second, third));

        assertFalse(PaywordUtilities.verifyPayment(hash, third, second));
        assertFalse(PaywordUtilities.verifyPayment(hash, third, first));
        assertFalse(PaywordUtilities.verifyPayment(hash, second, first));
    }
}
