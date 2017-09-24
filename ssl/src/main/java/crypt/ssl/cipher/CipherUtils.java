package crypt.ssl.cipher;

import crypt.ssl.CipherSuite;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;

public abstract class CipherUtils {

    private CipherUtils() {
    }

    public static byte[] encrypt(CipherSuite suite, byte[] iv, byte[] key, IOConsumer<OutputStream> consumer) {
        try {
            Cipher cipher = CipherFactory.getCipher(suite);

            IvParameterSpec ivParam = new IvParameterSpec(iv);
            SecretKeySpec keyParam = new SecretKeySpec(key, cipher.getAlgorithm());

            cipher.init(Cipher.ENCRYPT_MODE, keyParam, ivParam);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            try (CipherOutputStream cos = new CipherOutputStream(bos, cipher)) {
                consumer.accept(cos);
            }

            return bos.toByteArray();
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public interface IOConsumer<T> {

        void accept(T object) throws IOException;
    }
}
