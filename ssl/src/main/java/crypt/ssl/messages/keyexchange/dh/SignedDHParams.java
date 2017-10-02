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
                "\n\tserverDHParams(" +
                "\n\t\tP: " + serverDHParams.getP().toString(16) +
                ",\n\t\tG: " + serverDHParams.getG().toString(16) +
                ",\n\t\tYs: " + serverDHParams.getYs().toString(16) +
                "\n\t)" +
                ",\n\tsignatureAndHashAlgorithm: " + signatureAndHashAlgorithm +
                ",\n\tsignature: " + Hex.toHex(signature) +
                "\n)";
    }
}
