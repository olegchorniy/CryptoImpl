package crypt.payments.registration;

import crypt.payments.certificates.UserCertificate;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@AllArgsConstructor
public class User {

    private UUID id;
    private int balance;

    private int port;
    private String address;

    private LocalDateTime registrationDate;
    private UserCertificate certificate;
}
