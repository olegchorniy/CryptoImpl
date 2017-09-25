package crypt.ssl.cipher;

import crypt.ssl.CipherSuite;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;

public abstract class CipherUtils {

    private CipherUtils() {
    }

    public static byte[] encrypt(CipherSuite suite, byte[] iv, byte[] key, byte[] input) {
        return processInput(suite, Cipher.ENCRYPT_MODE, iv, key, input);
    }

    public static byte[] decrypt(CipherSuite suite, byte[] iv, byte[] key, byte[] input) {
        return processInput(suite, Cipher.DECRYPT_MODE, iv, key, input);
    }

    public static byte[] processInput(CipherSuite suite, int mode, byte[] iv, byte[] key, byte[] input) {
        try {
            Cipher cipher = CipherFactory.getCipher(suite);

            IvParameterSpec ivParam = new IvParameterSpec(iv);
            SecretKeySpec keyParam = new SecretKeySpec(key, cipher.getAlgorithm());

            cipher.init(mode, keyParam, ivParam);

            return cipher.doFinal(input);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
