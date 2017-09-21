package crypt.ssl.messages.keyexchange;

import lombok.Getter;

import java.math.BigInteger;

@Getter
public class ClientDHPublic {

    private BigInteger Yc;
}
