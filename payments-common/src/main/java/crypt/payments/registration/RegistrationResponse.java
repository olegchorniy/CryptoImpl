package crypt.payments.registration;

import crypt.payments.signatures.rsa.RSAPrivateKey;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RegistrationResponse {

    private User user;
    private RSAPrivateKey privateKey;
}
