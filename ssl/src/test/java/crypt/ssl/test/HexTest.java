package crypt.ssl.test;

import crypt.ssl.utils.Hex;
import org.junit.Assert;
import org.junit.Test;

public class HexTest {

    @Test
    public void testToHex() {
        Assert.assertEquals("00ff11", Hex.toHex(0xFF_11, 6));
    }
}
