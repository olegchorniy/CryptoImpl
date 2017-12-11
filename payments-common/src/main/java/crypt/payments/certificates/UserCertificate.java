package crypt.payments.certificates;

import crypt.payments.signatures.encoding.Encoder;
import crypt.payments.signatures.rsa.RSAPublicKey;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
@NoArgsConstructor
public class UserCertificate extends Certificate {

    private String broker;
    private UUID userId;

    public UserCertificate(String broker, UUID userId, String userName, LocalDateTime expirationDate, RSAPublicKey publicKey) {
        super(userName, expirationDate, publicKey);
        this.userId = userId;
        this.broker = broker;
    }

    @Override
    public byte[] encode() {
        return new Encoder()
                .putBytes(super.encode())
                .putUUID(this.userId)
                .putString(this.broker)
                .encode();
    }
}
