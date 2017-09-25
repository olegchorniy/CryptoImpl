package crypt.ssl.connection;

import crypt.ssl.CipherSuite;
import lombok.Builder;
import lombok.Getter;
import lombok.Singular;

import java.util.Arrays;
import java.util.List;


@Builder
@Getter
public class TlsConfigurer {

    @Singular
    private List<CipherSuite> suites;
    private Session session;

    public static TlsConfigurer forSuites(CipherSuite... suites) {
        return builder().suites(Arrays.asList(suites)).build();
    }

    public static TlsConfigurer forSession(Session session) {
        return builder().session(session).build();
    }
}
