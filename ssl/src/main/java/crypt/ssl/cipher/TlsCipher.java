package crypt.ssl.cipher;

import crypt.ssl.exceptions.TlsException;
import crypt.ssl.messages.ContentType;
import crypt.ssl.messages.ProtocolVersion;

public interface TlsCipher {

    byte[] encrypt(ContentType type, ProtocolVersion version, byte[] data);

    byte[] decrypt(ContentType type, ProtocolVersion version, byte[] data) throws TlsException;
}
