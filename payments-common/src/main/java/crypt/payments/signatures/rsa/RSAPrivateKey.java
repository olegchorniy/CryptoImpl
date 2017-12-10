package crypt.payments.signatures.rsa;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.math.BigInteger;

@Getter
@Setter
@EqualsAndHashCode(callSuper = true)
@ToString(callSuper = true)
public class RSAPrivateKey extends RSAKey {

    private BigInteger d;

    public RSAPrivateKey(BigInteger n, BigInteger d) {
        super(n);
        this.d = d;
    }
}
