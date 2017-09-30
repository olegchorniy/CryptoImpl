package crypt.ssl.messages.handshake;

import crypt.ssl.messages.VarLength;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.security.cert.X509Certificate;
import java.util.List;

@Getter
@Setter
@ToString
public class CertificateMessage extends HandshakeMessage {

    @VarLength(3)
    private List<X509Certificate> certificates;

    public CertificateMessage() {
        super(HandshakeType.CERTIFICATE);
    }

    public CertificateMessage(List<X509Certificate> certificates) {
        super(HandshakeType.CERTIFICATE);
        this.certificates = certificates;
    }
}