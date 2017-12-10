package crypt.payments.registration;

import crypt.payments.certificates.UserCertificate;
import crypt.payments.signatures.rsa.RSAPrivateKey;
import lombok.Data;

@Data
public class RegistrationResponse {

    private RSAPrivateKey privateKey;
    private UserCertificate certificate;
}
