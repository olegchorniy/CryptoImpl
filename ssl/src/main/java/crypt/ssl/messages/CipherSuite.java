package crypt.ssl.messages;

import lombok.Getter;

@Getter
@Size(2)
public enum CipherSuite implements TlsEnum {

    //TODO: define more methods (include NULL_NULL necessarily)
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA(0xC02F);

    private final int value;

    CipherSuite(int value) {
        this.value = value;
    }
}
