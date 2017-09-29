package crypt.ssl.keyexchange;

import crypt.ssl.TlsExceptions;
import crypt.ssl.connection.SecurityParameters;
import crypt.ssl.connection.TlsContext;
import crypt.ssl.encoding.Encoder;
import crypt.ssl.encoding.KeyExchangeDecoder;
import crypt.ssl.encoding.KeyExchangeEncoder;
import crypt.ssl.encoding.TlsEncoder;
import crypt.ssl.exceptions.TlsFatalException;
import crypt.ssl.messages.handshake.ServerKeyExchange;
import crypt.ssl.messages.keyexchange.dh.ClientDHPublic;
import crypt.ssl.messages.keyexchange.dh.ServerDHParams;
import crypt.ssl.messages.keyexchange.dh.SignedDHParams;
import crypt.ssl.signature.SignatureAndHashAlgorithm;
import crypt.ssl.signature.SignatureFactory;

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
    public void processServerKeyExchange(ServerKeyExchange serverKeyExchange) throws TlsFatalException {
        ByteBuffer data = serverKeyExchange.getData();
        SignedDHParams signedDHParams = KeyExchangeDecoder.readDHKEParams(data);

        checkSignature(signedDHParams);

        this.serverDHParams = signedDHParams.getServerDHParams();
    }

    private void checkSignature(SignedDHParams signedDHParams) throws TlsFatalException {
        try {
            Signature signature = getSignature(signedDHParams.getSignatureAndHashAlgorithm());
            SecurityParameters parameters = this.context.getSecurityParameters();

            update(signature, parameters.getClientRandom(), TlsEncoder::writeRandom);
            update(signature, parameters.getServerRandom(), TlsEncoder::writeRandom);
            update(signature, signedDHParams.getServerDHParams(), KeyExchangeEncoder::writeServerDHParams);

            if (!signature.verify(signedDHParams.getSignature())) {
                throw TlsExceptions.decryptError();
            }

        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private Signature getSignature(SignatureAndHashAlgorithm algorithm) throws InvalidKeyException {
        Signature signature = SignatureFactory.getInstance(algorithm);
        signature.initVerify(certificate);

        return signature;
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

    /* ------------------- Diffie-Hellman algorithm routines --------------------- */

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

    /* ------------------------ Signature Utils ---------------------- */

    private static <T> void update(Signature signature, T object, Encoder<T> encoder) throws SignatureException {
        signature.update(Encoder.writeToArray(object, encoder));
    }
}
