package crypt.payments.certificates;

import crypt.payments.signatures.encoding.Encoder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class UserCertificate extends Certificate {

    private String broker;

    @Override
    public byte[] encode() {
        return new Encoder()
                .putBytes(super.encode())
                .putString(this.broker)
                .encode();
    }
}
