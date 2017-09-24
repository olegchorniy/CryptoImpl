package crypt.ssl.messages;

import crypt.ssl.utils.Dumper;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.nio.ByteBuffer;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class RawMessage {

    private ContentType contentType;
    private ByteBuffer messageBody;

    @Override
    public String toString() {
        return "RawMessage(type=" + contentType + ")\n"
                + Dumper.dumpToString(messageBody);
    }
}
