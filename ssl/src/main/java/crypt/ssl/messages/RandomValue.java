package crypt.ssl.messages;


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
}
