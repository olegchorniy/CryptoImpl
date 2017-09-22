package crypt.ssl.signature;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;
import lombok.Getter;

@Getter
@Size(1)
public enum SignatureAlgorithm implements TlsEnum {

    ANONYMOUS(0),
    RSA(1),
    DSA(2),
    ECDSA(3);

    private final int value;

    SignatureAlgorithm(int value) {
        this.value = value;
    }
}
