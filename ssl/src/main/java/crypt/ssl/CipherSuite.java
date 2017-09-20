package crypt.ssl;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;
import lombok.Getter;

@Getter
@Size(2)
public enum CipherSuite implements TlsEnum {

    //TODO: define more methods (include NULL_NULL necessarily)

    // @formatter:off

    TLS_NULL_WITH_NULL_NULL              (0x0000),
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256   (0x00A0),
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256  (0x009E),
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 (0xC029),
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 (0xC031),
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA   (0xC02F),
    TLS_RSA_WITH_AES_128_CBC_SHA256      (0x003C),
    TLS_RSA_WITH_AES_128_GCM_SHA256      (0x009C);

    // @formatter:on

    private final int value;

    CipherSuite(int value) {
        this.value = value;
    }
}
