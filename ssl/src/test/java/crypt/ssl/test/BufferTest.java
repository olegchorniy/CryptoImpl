package crypt.ssl.test;

import crypt.ssl.connection.Buffer;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class BufferTest {

    @Test
    public void basicTest() {
        Buffer buffer = new Buffer();

        assertEquals(0, buffer.available());

        buffer.putBytes(bytes(0x71, 0x72, 0x73));

        assertEquals(3, buffer.available());
        assertArrayEquals(bytes(0x71, 0x72), buffer.getBytes(2));
        assertEquals(1, buffer.available());

        buffer.putBytes(bytes(0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67));

        assertEquals(8, buffer.available());
        assertArrayEquals(bytes(0x73, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67), buffer.peekBytes());
        assertEquals(8, buffer.available());
        assertArrayEquals(bytes(0x73, 0x61, 0x62, 0x63), buffer.getBytes(4));
        assertEquals(4, buffer.available());

        buffer.skip(2);

        assertEquals(2, buffer.available());
        assertArrayEquals(bytes(0x66, 0x67), buffer.getBytes());
    }

    private static byte[] bytes(int... values) {
        byte[] bytes = new byte[values.length];
        for (int i = 0; i < values.length; i++) {
            bytes[i] = (byte) values[i];
        }

        return bytes;
    }
}
