package crypt.ssl.messages.keyexchange;

import crypt.ssl.signature.SignatureAndHashAlgorithm;
import crypt.ssl.utils.Hex;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.nio.ByteBuffer;

@Getter
@AllArgsConstructor
public class SignedParams<T> {

    private T params; //or maybe better let subclasses to define this field?
    private SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    private ByteBuffer signature;

    @Override
    public String toString() {
        return "SignedDHParams(" +
                "params=" + params +
                ", signatureAndHashAlgorithm=" + signatureAndHashAlgorithm +
                ", signature=" + Hex.toHex(signature) +
                ')';
    }
}
