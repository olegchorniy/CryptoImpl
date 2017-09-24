package crypt.ssl.cipher;

import crypt.ssl.messages.TlsRecord;

public interface TlsCipher {

    byte[] encrypt(TlsRecord compressedRecord);

    byte[] decrypt(byte[] data);
}
