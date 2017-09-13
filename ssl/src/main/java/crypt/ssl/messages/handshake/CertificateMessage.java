package crypt.ssl.messages.handshake;

import crypt.ssl.messages.ASN1Certificate;
import crypt.ssl.messages.VarLength;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

@Getter
@Setter
public class CertificateMessage extends HandshakeMessage {

    @VarLength(3)
    private List<ASN1Certificate> certificates;

    public CertificateMessage() {
        super(HandshakeType.CERTIFICATE);
    }

    public CertificateMessage(List<ASN1Certificate> certificates) {
        super(HandshakeType.CERTIFICATE);
        this.certificates = certificates;
    }
}