package crypt.payments.registration;

import lombok.Data;

@Data
public class RegistrationRequest {

    private String name;

    private int port;
    private String address;
}
