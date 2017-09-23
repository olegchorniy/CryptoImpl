package crypt.ssl.messages.keyexchange.dh;


import crypt.ssl.signature.SignatureAndHashAlgorithm;
import crypt.ssl.utils.Hex;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class SignedDHParams {

    private ServerDHParams serverDHParams;
    private SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    private byte[] signature;

    @Override
    public String toString() {
        return "SignedDHParams(" +
                "serverDHParams=" + serverDHParams +
                ", signatureAndHashAlgorithm=" + signatureAndHashAlgorithm +
                ", signature=" + Hex.toHex(signature) +
                ')';
    }
}
