package crypt.ssl.messages.alert;

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
}
