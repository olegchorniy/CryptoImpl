package crypt.payments.certificates;

import crypt.payments.signatures.encoding.Encoder;
import crypt.payments.signatures.rsa.RSAPublicKey;
import lombok.*;

import java.time.LocalDateTime;

@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
@NoArgsConstructor
public class UserCertificate extends Certificate {

    private String broker;

    public UserCertificate(String broker, String userName, LocalDateTime expirationDate, RSAPublicKey publicKey) {
        super(userName, expirationDate, publicKey);
        this.broker = broker;
    }

    @Override
    public byte[] encode() {
        return new Encoder()
                .putBytes(super.encode())
                .putString(this.broker)
                .encode();
    }
}
