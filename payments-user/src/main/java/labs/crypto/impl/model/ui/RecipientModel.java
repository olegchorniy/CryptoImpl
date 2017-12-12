package labs.crypto.impl.model.ui;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.UUID;

@Getter
@AllArgsConstructor
public class RecipientModel {

    private UUID id;
    private String name;
    private String address;
    private OutgoingSessionModel session;
}
