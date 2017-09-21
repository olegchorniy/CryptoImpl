package crypt.ssl.testing;

import crypt.ssl.connection.RandomGenerator;
import crypt.ssl.utils.Dumper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Random;

public class AesTest {

    private static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    private static final String AES_CBC_PKCS_PADDING = "AES/CBC/PKCS7Padding";

    private static RandomGenerator random = new RandomGenerator(new Random());

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        byte[] iv = random.getBytes(16);
        byte[] key = random.getBytes(16);

        byte[] plainText = random.getBytes(1);
        byte[] cipherText = encrypt(plainText, key, iv);

        byte[] decryptedText = decrypt(cipherText, key, iv);

        System.out.println("PlainText");
        Dumper.dumpToStdout(plainText);

        System.out.println("CipherText");
        Dumper.dumpToStdout(cipherText);

        System.out.println("DecryptedText");
        Dumper.dumpToStdout(decryptedText);
    }

    private static byte[] encrypt(byte[] plainText, byte[] key, byte[] iv) throws GeneralSecurityException {
        return doTransformation(Cipher.ENCRYPT_MODE, plainText, key, iv);
    }

    private static byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv) throws GeneralSecurityException {
        return doTransformation(Cipher.DECRYPT_MODE, cipherText, key, iv);
    }

    private static byte[] doTransformation(int mode, byte[] text, byte[] key, byte[] iv) throws GeneralSecurityException {

        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        SecretKeySpec keySpec = new SecretKeySpec(key, "AES");

        Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING, "BC");
        cipher.init(mode, keySpec, ivSpec);

        return cipher.doFinal(text);
    }
}
