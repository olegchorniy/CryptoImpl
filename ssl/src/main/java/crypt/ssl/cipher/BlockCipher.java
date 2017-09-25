package crypt.ssl.cipher;

import crypt.ssl.CipherSuite;
import crypt.ssl.connection.KeyParameters;
import crypt.ssl.connection.TlsContext;
import crypt.ssl.encoding.Encoder;
import crypt.ssl.encoding.TlsEncoder;
import crypt.ssl.mac.MacFactory;
import crypt.ssl.messages.TlsRecord;
import crypt.ssl.utils.Bits;
import crypt.ssl.utils.RandomUtils;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.Arrays;
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

        int plainTextLength = content.length + mac.length;

        // Calculate padding length
        int blockLength = this.cipherSuite.getBlockSize();
        int paddingLength = blockLength - plainTextLength % blockLength;

        // Prepare encryption input
        byte[] input = new byte[plainTextLength + paddingLength];

        System.arraycopy(content, 0, input, 0, content.length);
        System.arraycopy(mac, 0, input, content.length, mac.length);
        addPadding(input, plainTextLength, paddingLength);

        // Encrypt data
        byte[] encryptedData = CipherUtils.encrypt(this.cipherSuite, iv, key, input);

        // Concat with IV and return the result
        return Bits.concat(iv, encryptedData);
    }

    private byte[] generateIv() {
        return RandomUtils.getBytes(this.random, this.cipherSuite.getBlockSize());
    }

    /*
        Record structure: iv | [content | mac | padding]
     */
    @Override
    public byte[] decrypt(TlsRecord encryptedRecord) {
        byte[] encryptedContent = encryptedRecord.getRecordBody();
        if (encryptedContent.length == 0) {
            //TODO: I know about possible empty encrypted messages. But should the IV be present regardless of the message length?
            return encryptedContent;
        }

        int blockSize = this.cipherSuite.getBlockSize();

        if (encryptedContent.length % blockSize != 0) {
            throw new RuntimeException("Bad padding or ... whatever");
        }

        // 0. Prepare parameters and decrypt record
        byte[] iv = Arrays.copyOfRange(encryptedContent, 0, blockSize);
        byte[] key = this.keyParams.getEncryptionKey();

        byte[] input = Arrays.copyOfRange(encryptedContent, blockSize, encryptedContent.length);
        byte[] plainText = CipherUtils.decrypt(this.cipherSuite, iv, key, input);

        // 1. Check padding
        int paddingStart = checkPadding(plainText);

        // 2. Check MAC
        int macLength = this.cipherSuite.getMacLength();

        byte[] content = Arrays.copyOfRange(plainText, 0, paddingStart - macLength);
        byte[] mac = Arrays.copyOfRange(plainText, content.length, paddingStart);

        TlsRecord decryptedRecord = new TlsRecord(
                encryptedRecord.getType(),
                encryptedRecord.getVersion(),
                content
        );

        if (!Arrays.equals(mac, calculateMac(decryptedRecord))) {
            throw new RuntimeException("Bad mac");
        }

        return content;
    }

    private void addPadding(byte[] input, int offset, int paddingLength) {
        for (int i = 0; i < paddingLength; i++) {
            input[offset + i] = (byte) (paddingLength - 1);
        }
    }

    private int checkPadding(byte[] input) {
        int paddingByte = Byte.toUnsignedInt(input[input.length - 1]);
        int paddingStart = input.length - 1 - paddingByte;

        for (int i = paddingStart; i < input.length - 1; i++) {
            if (Byte.toUnsignedInt(input[i]) != paddingByte) {
                throw new RuntimeException("bad padding");
            }
        }

        return paddingStart;
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
}
