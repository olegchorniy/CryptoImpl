package crypt.ssl.messages;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class Extension {

    @Size(2)
    private int extensionType;

    @VarLength(2)
    private byte[] data;
}
