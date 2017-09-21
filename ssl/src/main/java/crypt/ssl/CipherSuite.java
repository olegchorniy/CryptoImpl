package crypt.ssl;

import crypt.ssl.digest.DigestAlgorithm;
import crypt.ssl.keyexchange.KeyExchangeType;
import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;
import lombok.Getter;

@Getter
@Size(2)
public enum CipherSuite implements TlsEnum {

    // @formatter:off

    TLS_NULL_WITH_NULL_NULL              (0x0000),
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256   (0x00A0),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xC029),
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xC031),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA   (0xC02F),

    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256  (0x009E, KeyExchangeType.DHE, DigestAlgorithm.SHA256, 128, 256),
    TLS_RSA_WITH_AES_128_CBC_SHA256      (0x003C, KeyExchangeType.RSA, DigestAlgorithm.SHA256, 128, 256),
    TLS_RSA_WITH_AES_128_GCM_SHA256      (0x009C, KeyExchangeType.RSA, DigestAlgorithm.SHA256, 128, 256);

    // @formatter:on

    private final int value;

    private final KeyExchangeType keyExchangeType;
    private final DigestAlgorithm digestAlgorithm;
    private final int encryptionKeySize;

    //in TLS is the same as the length of the corresponding hash function output
    private final int macKeySize;

    CipherSuite(int value) {
        this(value, null, null, -1, -1);
    }

    CipherSuite(int value,
                KeyExchangeType keyExchangeType,
                DigestAlgorithm digestAlgorithm,
                int encryptionKeySize,
                int macKeySize) {
        this.value = value;
        this.keyExchangeType = keyExchangeType;
        this.digestAlgorithm = digestAlgorithm;
        this.encryptionKeySize = encryptionKeySize;
        this.macKeySize = macKeySize;
    }
}
