package crypt.payments.signatures.rsa;

import crypt.payments.signatures.Encodable;
import lombok.*;

import java.math.BigInteger;

@Getter
@Setter
@EqualsAndHashCode
@AllArgsConstructor
@ToString
public abstract class RSAKey implements Encodable {

    private BigInteger n;

    @Override
    public byte[] encode() {
        return this.n.toByteArray();
    }
}
