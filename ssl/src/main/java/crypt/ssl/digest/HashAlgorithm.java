package crypt.ssl.digest;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;
import lombok.Getter;

@Getter
@Size(1)
public enum HashAlgorithm implements TlsEnum {

    NONE(0),
    MD5(1),
    SHA1(2),
    SHA224(3),
    SHA256(4),
    SHA384(5),
    SHA512(6);

    private final int value;

    HashAlgorithm(int value) {
        this.value = value;
    }
}
