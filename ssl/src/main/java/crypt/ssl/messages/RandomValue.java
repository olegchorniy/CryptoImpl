package crypt.ssl.messages;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class RandomValue {

    @Size(32)
    private byte[] randomBytes;
}
