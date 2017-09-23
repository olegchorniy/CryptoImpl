package crypt.ssl.encoding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public interface Encoder<T> {

    void encode(OutputStream out, T t) throws IOException;

    /* ----------------------------- Adapters --------------------------------- */

    static <T> ByteBuffer writeToBuffer(T obj, Encoder<? super T> encoder) {
        return ByteBuffer.wrap(writeToArray(obj, encoder));
    }

    static <T> byte[] writeToArray(T obj, Encoder<? super T> encoder) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try {
            encoder.encode(bos, obj);
        } catch (IOException impossible) {
            throw new RuntimeException(impossible);
        }

        return bos.toByteArray();
    }
}
