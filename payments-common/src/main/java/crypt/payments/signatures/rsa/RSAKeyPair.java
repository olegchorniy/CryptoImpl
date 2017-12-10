package crypt.payments.signatures.rsa;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RSAKeyPair {

    private RSAPublicKey publicKey;
    private RSAPrivateKey privateKey;
}
