package crypt.ssl.connection;

import crypt.ssl.Constants;

import java.nio.ByteBuffer;

public class Buffer {

    public static final ByteBuffer EMPTY = ByteBuffer.allocate(0);

    private byte[] bytes;
    private int length;

    public Buffer() {
        this.reset();
    }

    /* ------------------------------------------------- */
    /* ----------------- Core methods ------------------ */
    /* ------------------------------------------------- */

    public void putBytes(byte[] src, int offset, int srcLength) {
        int targetLength = this.length + srcLength;

        ensureLength(targetLength);

        System.arraycopy(src, offset, this.bytes, this.length, srcLength);
        this.length += srcLength;
    }

    public void getBytes(byte[] dst, int offset, int length) {
        peekBytes(dst, offset, length);

        shiftLeft(length);

        this.length -= length;
    }

    public void peekBytes(byte[] dst, int offset, int length) {
        checkLength(length);

        System.arraycopy(this.bytes, 0, dst, offset, length);
    }

    public void skip(int amount) {
        checkLength(amount);

        shiftLeft(amount);

        this.length -= amount;
    }

    public void reset() {
        this.bytes = Constants.EMPTY;
        this.length = 0;
    }

    public boolean isEmpty() {
        return available() == 0;
    }

    public int available() {
        return this.length;
    }


    /* ------------------------------------------------- */
    /* ---------------- Derived methods ---------------- */
    /* ------------------------------------------------- */

    public void putBytes(byte[] src) {
        putBytes(src, 0, src.length);
    }

    public void putBytes(byte[] src, int srcLength) {
        putBytes(src, 0, srcLength);
    }

    public void getBytes(byte[] dst, int length) {
        getBytes(dst, 0, length);
    }

    public void peekBytes(byte[] dst, int length) {
        peekBytes(dst, 0, length);
    }

    /* ------------------------------------------------- */
    /* ----------- ByteBuffer specializations ---------- */
    /* ------------------------------------------------- */

    public void putBytes(ByteBuffer byteBuffer) {
        byte[] src = new byte[byteBuffer.remaining()];
        byteBuffer.get(src);

        putBytes(src);
    }

    public ByteBuffer getBytes() {
        if (isEmpty()) {
            return EMPTY;
        }

        return getBytes(available());
    }

    public ByteBuffer getBytes(int length) {
        byte[] dst = new byte[length];
        getBytes(dst, length);

        return ByteBuffer.wrap(dst);
    }

    public ByteBuffer peekBytes() {
        if (isEmpty()) {
            return EMPTY;
        }

        return peekBytes(available());
    }

    public ByteBuffer peekBytes(int length) {
        byte[] dst = new byte[length];
        peekBytes(dst, 0, length);

        return ByteBuffer.wrap(dst);
    }

    /* ------------------------------------------------- */
    /* --------------- Private methods ----------------- */
    /* ------------------------------------------------- */

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
