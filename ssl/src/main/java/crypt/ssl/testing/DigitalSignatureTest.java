package crypt.ssl.testing;

import crypt.ssl.messages.RandomValue;
import crypt.ssl.messages.keyexchange.dh.ServerDHParams;
import crypt.ssl.messages.keyexchange.dh.SignedDHParams;
import crypt.ssl.signature.SignatureFactory;
import crypt.ssl.utils.Bits;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.spec.RSAPublicKeySpec;

public class DigitalSignatureTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
    }

    private static Signature getInitializedSignature() throws Exception {
        BigInteger n = new BigInteger("21980448846462357417104592118159160173990204504821232096922754043337671748713765169794140312540778474822205370583024418175404780524203721243899480650840158726393409220544413491246147856495724055429520302870791675026997955821979642789486911161739403254913819410161396795890102166319520942900054446399194503155351923159971115643025258352426176615903045283618967025859734400016247838955847556358322608385536616290296771354800910217076072771266731364406329597762740279790823588856995196288031898870639592858859453112391188845007333358134184696214576453843126881761583799344079741770693142511983338301898942113346856928759");
        BigInteger e = new BigInteger("65537");

        Signature signature = Signature.getInstance("SHA1WithRSA", "BC");

        PublicKey key = KeyFactory.getInstance("RSA", "BC").generatePublic(new RSAPublicKeySpec(n, e));
        signature.initVerify(key);

        return signature;
    }

    public static boolean checkSignature(SignedDHParams signedDHParams,
                                         Certificate certificate,
                                         RandomValue clientRandom,
                                         RandomValue serverRandom) {

        try {
            Signature signAlg = SignatureFactory.getInstance(signedDHParams.getSignatureAndHashAlgorithm());
            signAlg.initVerify(certificate);

            ServerDHParams dhParams = signedDHParams.getServerDHParams();

            update(signAlg, clientRandom);
            update(signAlg, serverRandom);
            update(signAlg, dhParams.getP());
            update(signAlg, dhParams.getG());
            update(signAlg, dhParams.getYs());

            return signAlg.verify(signedDHParams.getSignature());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }


    private static void update(Signature signature, RandomValue randomValue) throws SignatureException {
        signature.update(Bits.toBytes32(randomValue.getGmtUnixTime()));
        signature.update(randomValue.getRandomBytes());
    }

    private static void update(Signature signature, BigInteger value) throws SignatureException {
        byte[] bytes = BigIntegers.asUnsignedByteArray(value);

        signature.update(Bits.toBytes16(bytes.length));
        signature.update(bytes);
    }
}
