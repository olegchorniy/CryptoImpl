package crypt.payments.signatures.encoding;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.Date;

public class Encoder {

    private final ByteArrayOutputStream buffer;

    public Encoder() {
        this.buffer = new ByteArrayOutputStream(1024);
    }

    public Encoder putString(String s) {
        this.putBytes(s.getBytes(StandardCharsets.UTF_8));

        return this;
    }

    public Encoder putLocalDateTime(LocalDateTime localDateTime) {
        this.putLocalDate(localDateTime.toLocalDate());
        this.putLocalTime(localDateTime.toLocalTime());

        return this;
    }

    public Encoder putLocalTime(LocalTime localTime) {
        this.putInt(localTime.getHour());
        this.putInt(localTime.getMinute());
        this.putInt(localTime.getSecond());
        this.putInt(localTime.getNano());

        return this;
    }

    public Encoder putLocalDate(LocalDate localDate) {
        this.putInt(localDate.getYear());
        this.putInt(localDate.getMonthValue());
        this.putInt(localDate.getDayOfMonth());

        return this;
    }

    public Encoder putDate(Date date) {
        this.putLong(date.getTime());

        return this;
    }

    public Encoder putLong(long v) {
        this.putInt((int) (v >>> 32));
        this.putInt((int) (v));

        return this;
    }

    public Encoder putBytes(byte[] bytes) {
        for (byte value : bytes) {
            this.buffer.write(value);
        }

        return this;
    }

    public Encoder putInt(int v) {
        this.buffer.write((v >>> 24) & 0xFF);
        this.buffer.write((v >>> 16) & 0xFF);
        this.buffer.write((v >>> 8) & 0xFF);
        this.buffer.write((v) & 0xFF);

        return this;
    }

    public byte[] encode() {
        return this.buffer.toByteArray();
    }
}
