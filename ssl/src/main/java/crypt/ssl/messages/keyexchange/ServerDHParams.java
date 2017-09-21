package crypt.ssl.messages.keyexchange;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.math.BigInteger;

@Getter
@AllArgsConstructor
public class ServerDHParams {

    private BigInteger p;
    private BigInteger g;
    private BigInteger Ys;
}
