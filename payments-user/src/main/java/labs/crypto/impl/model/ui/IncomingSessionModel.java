package labs.crypto.impl.model.ui;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.UUID;

@Getter
@AllArgsConstructor
public class IncomingSessionModel {

    private UUID sessionId;
    private Vendor user;
    private int amount;
    private String root;
}
