package crypt.ssl.messages.alert;

import crypt.ssl.messages.ContentType;
import crypt.ssl.messages.TlsMessage;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Alert implements TlsMessage {

    private AlertLevel level;
    private AlertDescription description;

    @Override
    public ContentType getContentType() {
        return ContentType.ALERT;
    }

    @Override
    public String toString() {
        return "Alert(" +
                "\n\tlevel: " + level +
                ",\n\tdescription: " + description +
                ')';
    }
}
