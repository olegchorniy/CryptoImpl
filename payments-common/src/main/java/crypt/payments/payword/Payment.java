package crypt.payments.payword;

import lombok.Data;

@Data
public class Payment {

    private int index;
    private byte[] payword;
}
