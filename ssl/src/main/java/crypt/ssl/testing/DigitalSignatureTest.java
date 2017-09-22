package crypt.ssl.testing;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;

public class DigitalSignatureTest {

    private static String dataBytes = "" +
            "00 80\n" +
            "ff ff ff ff ff ff ff ff c9 0f da a2 21 68 c2 34\n" +
            "c4 c6 62 8b 80 dc 1c d1 29 02 4e 08 8a 67 cc 74\n" +
            "02 0b be a6 3b 13 9b 22 51 4a 08 79 8e 34 04 dd\n" +
            "ef 95 19 b3 cd 3a 43 1b 30 2b 0a 6d f2 5f 14 37\n" +
            "4f e1 35 6d 6d 51 c2 45 e4 85 b5 76 62 5e 7e c6\n" +
            "f4 4c 42 e9 a6 37 ed 6b 0b ff 5c b6 f4 06 b7 ed\n" +
            "ee 38 6b fb 5a 89 9f a5 ae 9f 24 11 7c 4b 1f e6\n" +
            "49 28 66 51 ec e6 53 81 ff ff ff ff ff ff ff ff\n" +

            "00 01\n" +
            "02\n" +

            "00 80\n" +
            "1b b7 5b c0 da 22 ea c6 56 61 f1 fb c8\n" +
            "56 cf 44 05 d6 6b 31 11 e0 85 53 6a 0d 6e 02 b0\n" +
            "58 ff 63 de 52 2c 1d de 7a 18 8d 56 bd 47 b8 40\n" +
            "6a 50 03 0d f5 9a ac d7 34 ab 4d 71 21 d3 83 59\n" +
            "b9 dd 52 e7 db ea b6 ff f3 14 60 2e cc 80 ba c4\n" +
            "e9 57 1c 0d 51 42 70 ad 7a 0d cf 6f d1 e2 27 4e\n" +
            "aa 2b dd cd 53 8c 6d ed fc d1 00 8e 7e 5c e7 eb\n" +
            "be ac 10 08 dd 3c 0d 33 5a 49 86 ff 6c 6a 1f 90\n" +
            "dc 94 5c";

    private static String clientRandom = "" +
            "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F " +
            "10 11 12 13 14 15 16 17 18 19 1F 1B 1C 1D 1E 1F";

    private static String serverRandom = "59 c4 eb 05\n" +
            "73 d2 4b 76 67 fa 9f 7f e6 a7 67 7c 6b 84 04 e3 db e6 36 44 06 21 1f 47 99 65 3d 27";

    private static String signatureBytes = "61 2d 4b fe aa 38 6a ff 3b\n" +
            "66 eb 55 26 25 14 f1 87 39 b5 98 5f cc 1c 89 3c\n" +
            "12 87 2c ea 85 9b 94 1f 60 7e 3d 52 38 cf 48 a8\n" +
            "81 f2 76 1e 00 35 c1 d4 14 4a 41 b8 7e 1e af 0e\n" +
            "5c 29 27 9a 81 11 80 c5 1c 64 94 97 b1 df a2 71\n" +
            "40 3a 1a 34 e7 a4 1e 27 79 c2 68 e6 ac fa 95 c8\n" +
            "18 99 e9 ce 7c 68 ce c2 54 b8 16 a6 e0 8e 40 8b\n" +
            "a9 68 d8 0b e6 6b 0a 43 95 ca e6 e8 e8 6a 63 27\n" +
            "0a 49 93 58 bc 48 e9 3e 23 39 ed 5f 61 6f 99 c3\n" +
            "de 39 80 f9 db 3e ff 22 b6 b8 93 11 a8 85 1c 43\n" +
            "90 65 24 c1 31 8a 20 22 48 b9 76 29 e4 23 9d 94\n" +
            "d5 6c 86 36 05 83 07 8a bc 66 9c 8e 09 78 ca 87\n" +
            "74 8a 15 1f 0c f4 d8 77 ee 0a 8a dc a4 67 5d b1\n" +
            "87 9e 2a b1 60 81 64 52 f0 50 13 9a 54 a5 6f 60\n" +
            "c7 f8 9f 8e 08 85 7d 78 0d 33 6a ec cf e2 49 26\n" +
            "53 e1 a1 3d ba 26 98 3d b4 f0 6c f3 04 f1 4c 59\n" +
            "c6 c9 ab 3f 95 33 c5";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {

        BigInteger n = new BigInteger("21980448846462357417104592118159160173990204504821232096922754043337671748713765169794140312540778474822205370583024418175404780524203721243899480650840158726393409220544413491246147856495724055429520302870791675026997955821979642789486911161739403254913819410161396795890102166319520942900054446399194503155351923159971115643025258352426176615903045283618967025859734400016247838955847556358322608385536616290296771354800910217076072771266731364406329597762740279790823588856995196288031898870639592858859453112391188845007333358134184696214576453843126881761583799344079741770693142511983338301898942113346856928759");
        BigInteger e = new BigInteger("65537");

        Signature signature = Signature.getInstance("SHA1WithRSA", "BC");

        PublicKey key = KeyFactory.getInstance("RSA", "BC").generatePublic(new RSAPublicKeySpec(n, e));
        signature.initVerify(key);

        signature.update(Parser.parseSpacedHex(clientRandom));
        signature.update(Parser.parseSpacedHex(serverRandom));
        signature.update(Parser.parseSpacedHex(dataBytes));
        System.out.println(signature.verify(Parser.parseSpacedHex(signatureBytes)));
    }
}
