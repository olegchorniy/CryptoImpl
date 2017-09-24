package crypt.ssl.cipher;

import crypt.ssl.CipherSuite;
import crypt.ssl.connection.KeyParameters;
import crypt.ssl.connection.TlsContext;
import crypt.ssl.encoding.Encoder;
import crypt.ssl.encoding.TlsEncoder;
import crypt.ssl.mac.MacFactory;
import crypt.ssl.messages.TlsRecord;
import crypt.ssl.utils.Bits;
import crypt.ssl.utils.IO;
import crypt.ssl.utils.RandomUtils;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;

public class BlockCipher implements TlsCipher {

    private final Random random;
    private final KeyParameters keyParams;
    private final CipherSuite cipherSuite;

    private long sequenceNumber = 0;

    public BlockCipher(TlsContext context, KeyParameters keyParameters) {
        this.random = context.getRandom();
        this.cipherSuite = context.getSecurityParameters().getCipherSuite();
        this.keyParams = keyParameters;
    }

    /*
      opaque IV[SecurityParameters.record_iv_length];
      block-ciphered struct {
          opaque content[TLSCompressed.length];
          opaque MAC[SecurityParameters.mac_length];
          uint8 padding[GenericBlockCipher.padding_length];
          uint8 padding_length;
      };
     */
    @Override
    public byte[] encrypt(TlsRecord compressedRecord) {
        byte[] iv = generateIv();
        byte[] key = this.keyParams.getEncryptionKey();

        byte[] content = compressedRecord.getRecordBody();
        byte[] mac = calculateMac(compressedRecord);

        byte[] encryptedData = CipherUtils.encrypt(this.cipherSuite, iv, key, out -> {
            IO.writeBytes(out, content);
            IO.writeBytes(out, mac);

            addPadding(out, content.length + mac.length);
        });

        return Bits.concat(iv, encryptedData);
    }

    private void addPadding(OutputStream out, int contentLength) throws IOException {
        int blockLength = this.cipherSuite.getBlockSize();
        int paddingLength = blockLength - contentLength % blockLength;

        for (int i = 0; i < paddingLength; i++) {
            out.write(paddingLength - 1);
        }
    }

    private byte[] generateIv() {
        return RandomUtils.getBytes(this.random, this.cipherSuite.getBlockSize());
    }

    /*
     MAC(MAC_write_key, seq_num +
                        TLSCompressed.type +
                        TLSCompressed.version +
                        TLSCompressed.length +
                        TLSCompressed.fragment);
    */
    private byte[] calculateMac(TlsRecord record) {
        byte[] seqNumBytes = Bits.toBytes64(sequenceNumber++);
        byte[] encodedRecord = Encoder.writeToArray(record, TlsEncoder::writeRecord);

        HMac hmac = createHMac();

        hmac.update(seqNumBytes, 0, seqNumBytes.length);
        hmac.update(encodedRecord, 0, encodedRecord.length);

        byte[] hmacOut = new byte[hmac.getMacSize()];
        hmac.doFinal(hmacOut, 0);

        return hmacOut;
    }

    private HMac createHMac() {
        HMac hmac = MacFactory.createHmac(this.cipherSuite.getHashAlgorithm());
        hmac.init(new KeyParameter(this.keyParams.getMacKey()));

        return hmac;
    }

    @Override
    public byte[] decrypt(byte[] content) {
        throw new UnsupportedOperationException();
    }
}
