package crypt.ssl.keyexchange;

import crypt.ssl.connection.RandomGenerator;
import crypt.ssl.messages.ASN1Certificate;
import crypt.ssl.messages.handshake.ClientKeyExchange;
import crypt.ssl.messages.handshake.ServerKeyExchange;

public class DHEKeyExchange implements KeyExchange {

    private final RandomGenerator random;

    public DHEKeyExchange(RandomGenerator random) {
        this.random = random;
    }

    @Override
    public boolean requiresServerKeyExchange() {
        return true;
    }

    @Override
    public void processServerCertificate(ASN1Certificate serverCertificate) {

    }

    @Override
    public void processServerKeyExchange(ServerKeyExchange serverKeyExchange) {

    }

    @Override
    public ClientKeyExchange generateClientKeyExchange() {
        return null;
    }
}
