package crypt.ssl.messages;

import crypt.ssl.Constants;
import crypt.ssl.utils.Hex;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode
public class SessionId {

    public static final SessionId EMPTY = new SessionId(Constants.EMPTY);

    @VarLength(1) //max length = 32
    private byte[] value;

    @Override
    public String toString() {
        return Hex.toHex(value);
    }
}
