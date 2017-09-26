package crypt.ssl.encoding;

import crypt.ssl.messages.keyexchange.dh.ClientDHPublic;
import crypt.ssl.messages.keyexchange.rsa.PreMasterSecret;
import crypt.ssl.utils.IO;
import org.bouncycastle.util.BigIntegers;

import java.io.IOException;
import java.io.OutputStream;

public abstract class KeyExchangeEncoder {

    private KeyExchangeEncoder() {
    }

    public static void writeClientDH(OutputStream out, ClientDHPublic clientDHPublic) throws IOException {
        byte[] YcBytes = BigIntegers.asUnsignedByteArray(clientDHPublic.getYc());
        IO.writeOpaque16(out, YcBytes);
    }

    public static void writePreMasterSecret(OutputStream out, PreMasterSecret secret) throws IOException {
        IO.writeEnum(out, secret.getVersion());
        IO.writeBytes(out, secret.getRandom());
    }
}
