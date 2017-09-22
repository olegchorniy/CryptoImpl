package crypt.ssl.messages.keyexchange;


import crypt.ssl.signature.SignatureAndHashAlgorithm;
import crypt.ssl.utils.Hex;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.nio.ByteBuffer;

@Getter
@AllArgsConstructor
public class SignedDHParams {

    private ServerDHParams serverDHParams;
    private SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    private ByteBuffer signature;

    @Override
    public String toString() {
        return "SignedDHParams(" +
                "serverDHParams=" + serverDHParams +
                ", signatureAndHashAlgorithm=" + signatureAndHashAlgorithm +
                ", signature=" + Hex.toHex(signature) +
                ')';
    }
}
