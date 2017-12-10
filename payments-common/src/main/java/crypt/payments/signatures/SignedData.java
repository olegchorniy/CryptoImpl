package crypt.payments.signatures;

public interface SignedData extends Encodable {

    byte[] getSignature();

    void setSignature(byte[] signature);
}
