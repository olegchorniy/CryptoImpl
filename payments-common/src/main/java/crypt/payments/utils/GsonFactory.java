package crypt.payments.utils;

import com.google.gson.*;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public abstract class GsonFactory {

    private static final DateTimeFormatter DATE_TIME_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

    private GsonFactory() {
    }

    public static Gson createGson() {
        return new GsonBuilder()
                .registerTypeAdapter(byte[].class, byteArraySerializer())
                .registerTypeAdapter(byte[].class, byteArrayDeserializer())
                .registerTypeAdapter(LocalDateTime.class, localDateTimeSerializer())
                .registerTypeAdapter(LocalDateTime.class, localDateTimeDeserializer())
                .create();
    }

    private static JsonSerializer<byte[]> byteArraySerializer() {
        return (bytes, type, context) -> new JsonPrimitive(HexUtils.toHex(bytes));
    }

    private static JsonDeserializer<byte[]> byteArrayDeserializer() {
        return (json, type, context) -> HexUtils.fromHex(json.getAsString());
    }

    private static JsonSerializer<LocalDateTime> localDateTimeSerializer() {
        return (localDateTime, type, context) -> new JsonPrimitive(localDateTime.format(DATE_TIME_FORMATTER));
    }

    private static JsonDeserializer<LocalDateTime> localDateTimeDeserializer() {
        return (json, type, context) -> LocalDateTime.parse(json.getAsString(), DATE_TIME_FORMATTER);
    }

}
