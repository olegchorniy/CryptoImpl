package crypt.ssl.keyexchange;

import crypt.ssl.connection.RandomGenerator;
import crypt.ssl.encoding.KeyExchangeDecoder;
import crypt.ssl.messages.ASN1Certificate;
import crypt.ssl.messages.handshake.ClientKeyExchange;
import crypt.ssl.messages.handshake.ServerKeyExchange;
import crypt.ssl.messages.keyexchange.ServerDHParams;
import crypt.ssl.messages.keyexchange.SignedDHParams;

import java.nio.ByteBuffer;

public class DHEKeyExchange implements KeyExchange {

    private final RandomGenerator random;
    private ServerDHParams serverDHParams;

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
        ByteBuffer data = serverKeyExchange.getData();
        SignedDHParams signedDHParams = KeyExchangeDecoder.readDHKEParams(data);

        checkSignature(signedDHParams);

        this.serverDHParams = signedDHParams.getServerDHParams();
    }

    private void checkSignature(SignedDHParams signedDHParams) {
        //TODO: check signature
    }

    @Override
    public ClientKeyExchange generateClientKeyExchange() {
        ByteBuffer exchangeKeys = null;
        return new ClientKeyExchange(exchangeKeys);
    }
}
