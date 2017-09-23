package crypt.ssl.encoding;

import crypt.ssl.messages.keyexchange.dh.ClientDHPublic;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.OutputStream;

public abstract class KeyExchangeEncoder {

    private KeyExchangeEncoder() {
    }

    public static void writeClientDH(OutputStream out, ClientDHPublic clientDHPublic) throws IOException {
        IO.writeBigInteger16(out, clientDHPublic.getYc());
    }
}
