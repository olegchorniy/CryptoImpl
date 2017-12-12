package labs.crypto.impl.model.ui;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class PaywordModel {
    private boolean paid;
    private String hash;
}
