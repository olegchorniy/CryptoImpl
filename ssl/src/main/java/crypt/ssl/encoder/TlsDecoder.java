package crypt.ssl.encoder;

import crypt.ssl.messages.ContentType;
import crypt.ssl.messages.ProtocolVersion;
import crypt.ssl.messages.TlsRecord;
import crypt.ssl.utils.IO;

import java.io.IOException;
import java.io.InputStream;

import static crypt.ssl.utils.TlsEnumUtils.readEnum;

public abstract class TlsDecoder {

    private TlsDecoder() {
    }

    public static TlsRecord readRecord(InputStream in) throws IOException {
        ContentType type = readEnum(ContentType.class, in);
        ProtocolVersion version = readEnum(ProtocolVersion.class, in);

        int length = IO.readInt16(in);

        return null;
    }
}
