package crypt.ssl.keyexchange;

import crypt.ssl.exceptions.TlsFatalException;
import crypt.ssl.messages.handshake.ServerKeyExchange;

import java.security.cert.X509Certificate;

public interface KeyExchange {

    boolean requiresServerKeyExchange();

    // Necessary for the key encryption or for the signature verification
    void processServerCertificate(X509Certificate serverCertificate);

    void processServerKeyExchange(ServerKeyExchange serverKeyExchange) throws TlsFatalException;

    byte[] generateClientKeyExchange();

    byte[] generatePreMasterSecret();
}
