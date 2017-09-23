package crypt.ssl.messages.handshake;

import crypt.ssl.messages.ASN1Certificate;
import crypt.ssl.messages.VarLength;
import crypt.ssl.utils.CertificateDecoder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

@Getter
@Setter
@ToString
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

    public X509Certificate getDecodedCertificate(int i) {
        try {
            byte[] encodedCertificate = certificates.get(i).getContent();
            return CertificateDecoder.decodeCertificate(encodedCertificate);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
}