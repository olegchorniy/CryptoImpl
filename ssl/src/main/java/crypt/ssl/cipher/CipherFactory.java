package crypt.ssl.cipher;

import crypt.ssl.CipherSuite;
import crypt.ssl.utils.Assert;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public abstract class CipherFactory {

    private CipherFactory() {
    }

    public static Cipher getCipher(CipherSuite cipherSuite) {
        Assert.assertEquals(cipherSuite.getBulkCipherAlgorithm(), BulkCipherAlgorithm.AES);

        switch (cipherSuite.getCipherType()) {
            case AEAD_CIPHER:
                return getInstance("AES/GCM/NoPadding");
            case BLOCK_CIPHER:
                return getInstance("AES/CBC/NoPadding");
        }

        throw new IllegalArgumentException(cipherSuite.getCipherType() + " is not compliant with AES");
    }

    public static Cipher getInstance(String cipher) {
        try {
            return Cipher.getInstance(cipher, "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
