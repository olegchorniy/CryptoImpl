package labs.crypto.impl.model;

import lombok.Getter;
import lombok.Setter;

import java.util.Map;

@Getter
@Setter
public class RenderRequest {

    private String template;
    private Map<String, Object> params;
}
