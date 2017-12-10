package crypt.payments.payword;

import crypt.payments.signatures.SignedData;
import crypt.payments.certificates.UserCertificate;
import crypt.payments.signatures.encoding.Encoder;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
public class Commitment implements SignedData {

    private byte[] root;
    private String vendorName;
    private Date currentDate;
    private UserCertificate certificate;
    private byte[] signature;

    @Override
    public byte[] encode() {
        return new Encoder()
                .putBytes(this.root)
                .putString(this.vendorName)
                .putDate(this.currentDate)
                .putBytes(this.certificate.encode())
                .encode();
    }
}
