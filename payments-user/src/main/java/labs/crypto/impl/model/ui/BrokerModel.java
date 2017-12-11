package labs.crypto.impl.model.ui;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@AllArgsConstructor
@Getter
public class BrokerModel {

    private String name;
    private String address;
    private List<Vendor> vendors;
}
