package crypt.payments.signatures.rsa;

import crypt.payments.signatures.Encodable;
import crypt.payments.signatures.encoding.Encoder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.math.BigInteger;

@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class RSAPublicKey extends RSAKey implements Encodable {

    private BigInteger e;

    public RSAPublicKey(BigInteger n, BigInteger e) {
        super(n);
        this.e = e;
    }

    @Override
    public byte[] encode() {
        return new Encoder()
                .putBytes(super.encode())
                .putBytes(e.toByteArray())
                .encode();
    }
}
