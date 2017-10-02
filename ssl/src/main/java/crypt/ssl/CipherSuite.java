package crypt.ssl;

import crypt.ssl.cipher.BulkCipherAlgorithm;
import crypt.ssl.cipher.CipherType;
import crypt.ssl.digest.HashAlgorithm;
import crypt.ssl.keyexchange.KeyExchangeType;
import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;
import crypt.ssl.utils.TlsEnumUtils;
import lombok.Getter;

@Getter
@Size(2)
public enum CipherSuite implements TlsEnum {

    // @formatter:off

    TLS_NULL_WITH_NULL_NULL              (0x0000),

    /*
    Don't use without careful clarification of the PRF, HMac and Hash (Finished) used with a desired cipher suite.

    TLS_DH_RSA_WITH_AES_128_GCM_SHA256   (0x00A0),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256  (0x009E),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xC029),
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xC031),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA   (0xC02F),
    TLS_RSA_WITH_AES_128_GCM_SHA256      (0x009C),
    */

    TLS_DHE_RSA_WITH_AES_128_CBC_SHA     (0x0033,
            KeyExchangeType.DHE,
            HashAlgorithm.SHA1,
            CipherType.BLOCK_CIPHER,
            BulkCipherAlgorithm.AES,
            16,
            16,
            20,
            20
    ),

    TLS_RSA_WITH_AES_128_CBC_SHA      (0x002F,
            KeyExchangeType.RSA,
            HashAlgorithm.SHA1,
            CipherType.BLOCK_CIPHER,
            BulkCipherAlgorithm.AES,
            16,
            16,
            20,
            20
    ),

    TLS_RSA_WITH_AES_128_CBC_SHA256      (0x003C,
            KeyExchangeType.RSA,
            HashAlgorithm.SHA256,
            CipherType.BLOCK_CIPHER,
            BulkCipherAlgorithm.AES,
            16,
            16,
            32,
            32
    );

    // @formatter:on

    private final int value;

    private final KeyExchangeType keyExchangeType;
    private final HashAlgorithm hashAlgorithm;
    private final CipherType cipherType;
    private final BulkCipherAlgorithm bulkCipherAlgorithm;

    private final int blockSize;
    private final int encryptionKeySize;

    //in TLS is the same as the length of the corresponding hash function output
    private final int macLength;
    private final int macKeyLength;

    CipherSuite(int value) {
        this(value, null, null, null, null, -1, -1, -1, -1);
    }

    CipherSuite(int value,
                KeyExchangeType keyExchangeType,
                HashAlgorithm hashAlgorithm,
                CipherType cipherType,
                BulkCipherAlgorithm bulkCipherAlgorithm,
                int blockSize,
                int encryptionKeySize,
                int macLength,
                int macKeyLength) {
        this.value = value;
        this.keyExchangeType = keyExchangeType;
        this.hashAlgorithm = hashAlgorithm;
        this.cipherType = cipherType;
        this.bulkCipherAlgorithm = bulkCipherAlgorithm;
        this.blockSize = blockSize;
        this.encryptionKeySize = encryptionKeySize;
        this.macLength = macLength;
        this.macKeyLength = macKeyLength;
    }

    //TODO: define properly for AEAD ciphers
    public int getFixedIvSize() {
        return 0;
    }

    @Override
    public String toString() {
        return TlsEnumUtils.toString(this);
    }
}
