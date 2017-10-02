package crypt.ssl.messages.keyexchange.dh;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.math.BigInteger;

@Getter
@AllArgsConstructor
public class ClientDHPublic {

    private BigInteger Yc;

    @Override
    public String toString() {
        return "ClientDHPublic(" +
                "\n\tYc: " + Yc.toString(16) +
                "\n)";
    }
}
