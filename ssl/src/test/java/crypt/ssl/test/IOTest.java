package crypt.ssl.test;

import crypt.ssl.utils.IO;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import static org.junit.Assert.assertArrayEquals;

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
}
