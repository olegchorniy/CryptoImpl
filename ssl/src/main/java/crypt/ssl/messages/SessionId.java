package crypt.ssl.messages;

import crypt.ssl.Constants;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class SessionId {

    public static final SessionId EMPTY = new SessionId(Constants.EMPTY);

    @VarLength(1) //max length = 32
    private byte[] value;
}
