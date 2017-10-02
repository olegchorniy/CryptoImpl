package crypt.ssl.messages;


import crypt.ssl.utils.Bits;
import crypt.ssl.utils.Hex;
import crypt.ssl.utils.RandomUtils;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.Random;

@Getter
@Setter
@AllArgsConstructor
public class RandomValue {

    @Size(4)
    private int gmtUnixTime;

    @Size(28)
    private byte[] randomBytes;

    @Override
    public String toString() {
        return "gmtUnixTime: " + Hex.toHex32(gmtUnixTime) +
                ", randomBytes: " + Hex.toHex(randomBytes);
    }

    public byte[] toByteArray() {
        return Bits.concat(Bits.toBytes32(gmtUnixTime), randomBytes);
    }

    public static RandomValue create(Random random) {
        int gmtUnixTime = random.nextInt();
        byte[] randomBytes = RandomUtils.getBytes(random, 28);

        return new RandomValue(gmtUnixTime, randomBytes);
    }
}
