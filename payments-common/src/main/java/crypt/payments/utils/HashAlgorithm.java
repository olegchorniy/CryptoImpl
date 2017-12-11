package crypt.payments.utils;

import lombok.Getter;

@Getter
public enum HashAlgorithm {
    MD5("MD5"),
    SHA1("SHA-1"),
    SHA_256("SHA-256"),
    SHA3_256("SHA3-256");

    private final String value;

    HashAlgorithm(String value) {
        this.value = value;
    }
}
