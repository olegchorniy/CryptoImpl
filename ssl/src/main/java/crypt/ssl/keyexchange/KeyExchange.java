package crypt.ssl.keyexchange;

import crypt.ssl.messages.ASN1Certificate;
import crypt.ssl.messages.handshake.ClientKeyExchange;
import crypt.ssl.messages.handshake.ServerKeyExchange;

public interface KeyExchange {

    boolean requiresServerKeyExchange();

    // Necessary for the key encryption or for the signature verification
    void processServerCertificate(ASN1Certificate serverCertificate);

    void processServerKeyExchange(ServerKeyExchange serverKeyExchange);

    ClientKeyExchange generateClientKeyExchange();
}
