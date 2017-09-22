package crypt.ssl.connection;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class TlsContext {

    private RandomGenerator generator;
    private SecurityParameters securityParameters;
}
