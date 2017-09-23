package crypt.ssl.keyexchange;

import crypt.ssl.connection.TlsContext;
import crypt.ssl.encoding.Encoder;
import crypt.ssl.encoding.KeyExchangeDecoder;
import crypt.ssl.encoding.KeyExchangeEncoder;
import crypt.ssl.messages.handshake.ServerKeyExchange;
import crypt.ssl.messages.keyexchange.dh.ClientDHPublic;
import crypt.ssl.messages.keyexchange.dh.ServerDHParams;
import crypt.ssl.messages.keyexchange.dh.SignedDHParams;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.X509Certificate;

public class DHEKeyExchange implements KeyExchange {

    private final TlsContext context;
    private ServerDHParams serverDHParams;
    private X509Certificate certificate;
    private PrivateKey clientPrivateKey;

    public DHEKeyExchange(TlsContext context) {
        //TODO: unused. Why?
        this.context = context;
    }

    @Override
    public boolean requiresServerKeyExchange() {
        return true;
    }

    @Override
    public void processServerCertificate(X509Certificate serverCertificate) {
        this.certificate = serverCertificate;
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
    public byte[] generateClientKeyExchange() {
        try {
            // Generate client key pair based on P and G received from the remove server
            KeyPair clientKeyPair = generateClientDHKeyPair(this.serverDHParams);

            //Store private part for the further common secret generation
            this.clientPrivateKey = clientKeyPair.getPrivate();

            //Perform several format transformations and return client public key to be sent to the server
            DHPublicKeySpec clientPublicKeySpec = toKeySpec(clientKeyPair.getPublic());
            ClientDHPublic clientDHPublic = new ClientDHPublic(clientPublicKeySpec.getY());

            return Encoder.writeToArray(clientDHPublic, KeyExchangeEncoder::writeClientDH);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public byte[] generatePreMasterSecret() {
        try {
            PublicKey serverPublicKey = toPublicKey(this.serverDHParams);

            return generateCommonSecret(this.clientPrivateKey, serverPublicKey);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyPair generateClientDHKeyPair(ServerDHParams serverDHParams) throws GeneralSecurityException {
        BigInteger p = serverDHParams.getP();
        BigInteger g = serverDHParams.getG();

        DHParameterSpec dhParams = new DHParameterSpec(p, g);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BC");
        keyPairGenerator.initialize(dhParams);

        return keyPairGenerator.generateKeyPair();
    }

    private static DHPublicKeySpec toKeySpec(PublicKey publicKey) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");
        return keyFactory.getKeySpec(publicKey, DHPublicKeySpec.class);
    }

    private static PublicKey toPublicKey(ServerDHParams dhParams) throws GeneralSecurityException {
        KeyFactory keyFactory = KeyFactory.getInstance("DH", "BC");

        DHPublicKeySpec keySpec = new DHPublicKeySpec(
                dhParams.getYs(),
                dhParams.getP(),
                dhParams.getG()
        );

        return keyFactory.generatePublic(keySpec);
    }

    private static byte[] generateCommonSecret(PrivateKey clientPrivateKey, PublicKey serverPublicKey) throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH", "BC");
        keyAgreement.init(clientPrivateKey);
        keyAgreement.doPhase(serverPublicKey, true);

        return keyAgreement.generateSecret();
    }
}
