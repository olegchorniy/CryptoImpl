package crypt.ssl.encoding;

import crypt.ssl.digest.HashAlgorithm;
import crypt.ssl.messages.keyexchange.dh.ServerDHParams;
import crypt.ssl.messages.keyexchange.dh.SignedDHParams;
import crypt.ssl.signature.SignatureAlgorithm;
import crypt.ssl.signature.SignatureAndHashAlgorithm;
import crypt.ssl.utils.IO;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public abstract class KeyExchangeDecoder {

    private KeyExchangeDecoder() {
    }

    public static SignedDHParams readDHKEParams(ByteBuffer buffer) {
        ServerDHParams serverDHParams = readServerDHParams(buffer);

        HashAlgorithm hashAlgorithm = IO.readEnum(buffer, HashAlgorithm.class);
        SignatureAlgorithm signatureAlgorithm = IO.readEnum(buffer, SignatureAlgorithm.class);

        int sigLength = IO.readInt16(buffer);
        byte[] signature = IO.readBytes(buffer, sigLength);

        return new SignedDHParams(
                serverDHParams,
                new SignatureAndHashAlgorithm(hashAlgorithm, signatureAlgorithm),
                signature
        );
    }

    private static ServerDHParams readServerDHParams(ByteBuffer buffer) {
        BigInteger p = IO.readBigInteger16(buffer);
        BigInteger g = IO.readBigInteger16(buffer);
        BigInteger Ys = IO.readBigInteger16(buffer);

        return new ServerDHParams(p, g, Ys);
    }
}
