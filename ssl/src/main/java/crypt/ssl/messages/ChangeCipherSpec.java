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

    @Size(1)
    private int type;
}
