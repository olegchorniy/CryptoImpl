package crypt.ssl.messages;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ApplicationData implements TlsMessage {

    private byte[] data;

    @Override
    public ContentType getContentType() {
        return ContentType.APPLICATION_DATA;
    }
}
