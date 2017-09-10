package crypt.ssl.messages;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class RandomValue {

    @Size(4)
    private int gmtUnixTime;

    @Size(28)
    private byte[] randomBytes;
}
