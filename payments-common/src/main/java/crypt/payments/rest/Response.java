package crypt.payments.rest;

import java.util.HashMap;

public class Response extends HashMap<String, Object> {

    public Response add(String key, Object value) {
        this.put(key, value);

        return this;
    }
}
