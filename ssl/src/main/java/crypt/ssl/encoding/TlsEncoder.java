package crypt.ssl.encoding;

import crypt.ssl.messages.TlsRecord;

import java.io.IOException;
import java.io.OutputStream;

public abstract class TlsEncoder {

    private TlsEncoder() {
    }

    public static void writeRecord(OutputStream out, TlsRecord record) throws IOException {

    }
}
