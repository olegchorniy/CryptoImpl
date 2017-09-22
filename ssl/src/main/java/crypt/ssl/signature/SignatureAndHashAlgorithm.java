package crypt.ssl.signature;

import crypt.ssl.digest.HashAlgorithm;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

@Getter
@AllArgsConstructor
@ToString
public class SignatureAndHashAlgorithm {

    private HashAlgorithm hashAlgorithm;
    private SignatureAlgorithm signatureAlgorithm;
}
