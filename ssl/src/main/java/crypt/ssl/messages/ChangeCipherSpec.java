package crypt.ssl.messages;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ChangeCipherSpec implements TlsMessage {

    public static final ChangeCipherSpec INSTANCE = new ChangeCipherSpec(1);

    @Size(1)
    private int type;

    @Override
    public ContentType getContentType() {
        return ContentType.CHANGE_CIPHER_SPEC;
    }
}
