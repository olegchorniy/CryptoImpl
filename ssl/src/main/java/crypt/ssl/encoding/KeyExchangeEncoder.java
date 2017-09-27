package crypt.ssl.encoding;

import crypt.ssl.messages.keyexchange.dh.ClientDHPublic;
import crypt.ssl.messages.keyexchange.dh.ServerDHParams;
import crypt.ssl.messages.keyexchange.rsa.PreMasterSecret;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.OutputStream;

public abstract class KeyExchangeEncoder {

    private KeyExchangeEncoder() {
    }

    public static void writeServerDHParams(OutputStream out, ServerDHParams params) throws IOException {
        IO.writeBigInteger(out, params.getP());
        IO.writeBigInteger(out, params.getG());
        IO.writeBigInteger(out, params.getYs());
    }

    public static void writeClientDH(OutputStream out, ClientDHPublic clientDHPublic) throws IOException {
        IO.writeBigInteger(out, clientDHPublic.getYc());
    }

    public static void writePreMasterSecret(OutputStream out, PreMasterSecret secret) throws IOException {
        IO.writeEnum(out, secret.getVersion());
        IO.writeBytes(out, secret.getRandom());
    }
}
