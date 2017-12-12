package labs.crypto.impl.model.ui;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;
import java.util.UUID;

@Getter
@AllArgsConstructor
public class OutgoingSessionModel {

    private UUID sessionId;
    private int transferredAmount;
    private List<PaywordModel> paywords;
}
