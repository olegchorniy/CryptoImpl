package labs.crypto.impl.model.ui;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class Vendor {

    private UUID id;
    private String name;
    private String address;
    private LocalDateTime registrationDate;
    private UUID outgoingSessionId;
}
