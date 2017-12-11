package crypt.payments.registration;

import crypt.payments.certificates.UserCertificate;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class User {

    private volatile int balance;

    private int port;
    private String address;

    private LocalDateTime registrationDate;
    private UserCertificate certificate;
}
