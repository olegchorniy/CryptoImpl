package crypt.payments.payword;

import crypt.payments.certificates.UserCertificate;
import crypt.payments.signatures.SignedData;
import crypt.payments.signatures.encoding.Encoder;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Commitment implements SignedData {

    private byte[] root;
    // Must be explicitly checked by the recipient and by the broker
    private UUID recipientId;
    // TODO: why do we need this field?
    private LocalDateTime currentDate;
    private UserCertificate certificate;
    private byte[] signature;

    @Override
    public byte[] encode() {
        return new Encoder()
                .putBytes(this.root)
                .putUUID(this.recipientId)
                .putLocalDateTime(this.currentDate)
                .putEncodable(this.certificate)
                .encode();
    }
}
