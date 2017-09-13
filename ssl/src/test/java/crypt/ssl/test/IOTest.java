package crypt.ssl.test;

import crypt.ssl.utils.IO;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class IOTest {

    @Test
    public void writeIntTest() throws IOException {
        int testValue = 0x04030201;

        assertArrayEquals(new byte[]{0x04, 0x03, 0x02, 0x01}, writeToArray(testValue, 4));
        assertArrayEquals(new byte[]{0x03, 0x02, 0x01}, writeToArray(testValue, 3));
        assertArrayEquals(new byte[]{0x02, 0x01}, writeToArray(testValue, 2));
        assertArrayEquals(new byte[]{0x01}, writeToArray(testValue, 1));
        assertArrayEquals(new byte[]{}, writeToArray(testValue, 0));
    }

    private static byte[] writeToArray(int value, int bytes) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        IO.writeInt(bos, value, bytes);

        return bos.toByteArray();
    }

    @Test
    public void readIntFromByteBufferTest() {
        //@formatter:off
        byte[] testArray = {0x04, 0x03, 0x02, 0x01};

        assertEquals(0x04,       IO.readInt8(ByteBuffer.wrap(testArray)));
        assertEquals(0x0403,     IO.readInt16(ByteBuffer.wrap(testArray)));
        assertEquals(0x040302,   IO.readInt24(ByteBuffer.wrap(testArray)));
        assertEquals(0x04030201, IO.readInt32(ByteBuffer.wrap(testArray)));
        //@formatter:on
    }

    @Test
    public void readBytesTest() {
        byte[] testArray = {0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};

        ByteBuffer srcBuffer = ByteBuffer.wrap(testArray);

        assertArrayEquals(new byte[]{0x07, 0x06, 0x05}, IO.readBytes(srcBuffer, 3));
        assertEquals(4, srcBuffer.remaining());
    }
}
