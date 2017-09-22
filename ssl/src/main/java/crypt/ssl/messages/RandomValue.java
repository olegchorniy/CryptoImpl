package crypt.ssl.messages;


import crypt.ssl.utils.Hex;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class RandomValue {

    @Size(4)
    private int gmtUnitTime;

    @Size(28)
    private byte[] randomBytes;

    @Override
    public String toString() {
        return "RandomValue(" +
                "gmtUnitTime=" + Hex.toHex32(gmtUnitTime) +
                ", randomBytes=" + Hex.toHex(randomBytes) +
                ')';
    }
}
