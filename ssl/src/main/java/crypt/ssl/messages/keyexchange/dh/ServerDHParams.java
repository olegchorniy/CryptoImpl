package crypt.ssl.messages.keyexchange.dh;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.ToString;

import java.math.BigInteger;

@Getter
@AllArgsConstructor
@ToString
public class ServerDHParams {

    private BigInteger p;
    private BigInteger g;
    private BigInteger Ys;
}
