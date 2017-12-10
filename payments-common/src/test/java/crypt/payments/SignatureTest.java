package crypt.payments;

import crypt.payments.signatures.SignatureUtils;
import crypt.payments.signatures.SignedData;
import crypt.payments.signatures.rsa.RSAKeyFactory;
import crypt.payments.signatures.rsa.RSAKeyPair;
import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.Security;

public class SignatureTest {

    @Before
    public void setUp() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void signatureTest() {
        RSAKeyPair keyPair = RSAKeyFactory.generateKeyPair(512);

        SimpleSignedData signedData = new SimpleSignedData(new byte[]{1, 2, 3, 126, 127, (byte) -127, (byte) -128});

        SignatureUtils.sign(signedData, keyPair.getPrivateKey());
        boolean valid = SignatureUtils.verify(signedData, keyPair.getPublicKey());

        Assert.assertTrue(valid);
    }


    @Getter
    @Setter
    private static class SimpleSignedData implements SignedData {

        private byte[] data;
        private byte[] signature;

        public SimpleSignedData(byte[] data) {
            this.data = data;
        }

        @Override
        public byte[] encode() {
            return this.data;
        }
    }
}