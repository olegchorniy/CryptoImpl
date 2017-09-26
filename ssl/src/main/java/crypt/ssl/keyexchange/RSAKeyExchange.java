package crypt.ssl.keyexchange;

import crypt.ssl.cipher.CipherUtils;
import crypt.ssl.connection.TlsContext;
import crypt.ssl.encoding.Encoder;
import crypt.ssl.encoding.KeyExchangeEncoder;
import crypt.ssl.messages.ProtocolVersion;
import crypt.ssl.messages.handshake.ServerKeyExchange;
import crypt.ssl.messages.keyexchange.rsa.PreMasterSecret;
import crypt.ssl.utils.IO;
import crypt.ssl.utils.RandomUtils;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Random;

public class RSAKeyExchange implements KeyExchange {

    private final Random random;
    private final ProtocolVersion version;
    private PublicKey serverPublicKey;
    private byte[] preMasterSecret;

    public RSAKeyExchange(TlsContext context) {
        this.random = context.getRandom();
        this.version = context.getVersion();
    }

    @Override
    public boolean requiresServerKeyExchange() {
        return false;
    }

    @Override
    public void processServerCertificate(X509Certificate serverCertificate) {
        this.serverPublicKey = serverCertificate.getPublicKey();
    }

    @Override
    public void processServerKeyExchange(ServerKeyExchange serverKeyExchange) {
        throw new IllegalStateException("Should never be called");
    }

    @Override
    public byte[] generateClientKeyExchange() {
        byte[] random = RandomUtils.getBytes(this.random, 46);

        PreMasterSecret secret = PreMasterSecret.builder()
                .version(this.version)
                .random(random)
                .build();

        byte[] preMasterSecret = Encoder.writeToArray(secret, KeyExchangeEncoder::writePreMasterSecret);
        this.preMasterSecret = preMasterSecret;

        byte[] encryptedSecret = rsaEncrypt(preMasterSecret);

        return Encoder.writeToArray(encryptedSecret, IO::writeOpaque16);
    }

    @Override
    public byte[] generatePreMasterSecret() {
        return this.preMasterSecret;
    }

    private byte[] rsaEncrypt(byte[] preMasterSecret) {
        return CipherUtils.encrypt("RSA/None/PKCS1Padding", this.serverPublicKey, preMasterSecret);
    }
}
