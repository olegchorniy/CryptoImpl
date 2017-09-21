package crypt.ssl.messages.keyexchange;


import lombok.AllArgsConstructor;
import lombok.Getter;

import java.nio.ByteBuffer;

@Getter
@AllArgsConstructor
public class SignedDHParams {

    private ServerDHParams serverDHParams;
    private ByteBuffer signature;
}
