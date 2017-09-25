package crypt.ssl.cipher;

import crypt.ssl.exceptions.TlsException;
import crypt.ssl.messages.TlsRecord;

public interface TlsCipher {

    byte[] encrypt(TlsRecord compressedRecord);

    byte[] decrypt(TlsRecord encryptedRecord) throws TlsException;
}
