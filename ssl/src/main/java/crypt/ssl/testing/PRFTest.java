package crypt.ssl.testing;

import crypt.ssl.digest.HashAlgorithm;
import crypt.ssl.prf.DigestPRF;
import crypt.ssl.prf.PRF;
import crypt.ssl.utils.Dumper;
import org.bouncycastle.crypto.prng.RandomGenerator;
import org.bouncycastle.crypto.tls.*;

import java.security.SecureRandom;
import java.util.Arrays;

public class PRFTest {

    public static void main(String[] args) {
        TlsContext ctx = fakeContext(PRFAlgorithm.tls_prf_sha256);

        PRF prf = new DigestPRF(HashAlgorithm.SHA256);

        byte[] key = {1, 2, 3, 4, 5, 6};
        String label = "my test label";
        byte[] seed = {0xC, 0xA, 0xF, 0xE, 0xB, 0xA, 0xB, 0xE};
        int outputSize = 40;

        byte[] myPrf = prf.compute(key, label, seed, outputSize);
        byte[] bcPrf = TlsUtils.PRF(ctx, key, label, seed, outputSize);

        System.out.println(Arrays.equals(myPrf, bcPrf));

        System.out.println("My PRF");
        Dumper.dumpToStdout(myPrf);

        System.out.println("BC PRF");
        Dumper.dumpToStdout(bcPrf);
    }

    private static TlsContext fakeContext(int prfAlgorithm) {
        return new TlsContext() {
            @Override
            public RandomGenerator getNonceRandomGenerator() {
                return null;
            }

            @Override
            public SecureRandom getSecureRandom() {
                return null;
            }

            @Override
            public SecurityParameters getSecurityParameters() {
                return new SecurityParameters() {
                    @Override
                    public int getPrfAlgorithm() {
                        return prfAlgorithm;
                    }
                };
            }

            @Override
            public boolean isServer() {
                return false;
            }

            @Override
            public ProtocolVersion getClientVersion() {
                return null;
            }

            @Override
            public ProtocolVersion getServerVersion() {
                return ProtocolVersion.TLSv12;
            }

            @Override
            public TlsSession getResumableSession() {
                return null;
            }

            @Override
            public Object getUserObject() {
                return null;
            }

            @Override
            public void setUserObject(Object userObject) {

            }

            @Override
            public byte[] exportKeyingMaterial(String asciiLabel, byte[] context_value, int length) {
                return new byte[0];
            }
        };
    }
}
