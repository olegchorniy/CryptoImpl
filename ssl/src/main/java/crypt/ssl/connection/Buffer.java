package crypt.ssl.connection;

import crypt.ssl.CommonConstants;

public class Buffer {

    private byte[] bytes;
    private int length;

    public Buffer() {
        this.reset();
    }

    public void reset() {
        this.bytes = CommonConstants.EMPTY;
        this.length = 0;
    }

    public int available() {
        return this.length;
    }

    public void putBytes(byte[] src) {
        putBytes(src, 0, src.length);
    }

    public void putBytes(byte[] src, int srcLength) {
        putBytes(src, 0, srcLength);
    }

    public void putBytes(byte[] src, int offset, int srcLength) {
        int targetLength = this.length + srcLength;

        ensureLength(targetLength);

        System.arraycopy(src, offset, this.bytes, this.length, srcLength);
        this.length += srcLength;
    }

    public byte[] getBytes() {
        int available = available();
        if (available == 0) {
            return CommonConstants.EMPTY;
        }

        byte[] dst = new byte[available];
        getBytes(dst, available);

        return dst;
    }

    public byte[] getBytes(int length) {
        byte[] dst = new byte[length];
        getBytes(dst, length);

        return dst;
    }

    public void getBytes(byte[] dst, int length) {
        getBytes(dst, 0, length);
    }

    public void getBytes(byte[] dst, int offset, int length) {
        peekBytes(dst, offset, length);

        shiftLeft(length);

        this.length -= length;
    }

    public byte[] peekBytes() {
        int available = available();
        if (available == 0) {
            return CommonConstants.EMPTY;
        }

        byte[] dst = new byte[available];
        peekBytes(dst, available);

        return dst;
    }

    public void peekBytes(byte[] dst, int length) {
        peekBytes(dst, 0, length);
    }

    public void peekBytes(byte[] dst, int offset, int length) {
        checkLength(length);

        System.arraycopy(this.bytes, 0, dst, offset, length);
    }

    private void checkLength(int requiredBytes) {
        int availableBytes = available();
        if (requiredBytes > availableBytes) {
            throw new IllegalStateException("Buffer doesn't contain necessary amount of bytes. " +
                    "Required = " + requiredBytes + ", available = " + availableBytes);
        }
    }

    private void shiftLeft(int positions) {
        for (int i = positions; i < this.length; i++) {
            this.bytes[i - positions] = this.bytes[i];
        }
    }

    private void ensureLength(int targetLength) {
        int currentLength = this.bytes.length;
        if (currentLength < targetLength) {
            int newLength = Math.max(currentLength << 1, targetLength);
            byte[] newArray = new byte[newLength];

            System.arraycopy(this.bytes, 0, newArray, 0, this.length);
            this.bytes = newArray;
        }
    }
}
