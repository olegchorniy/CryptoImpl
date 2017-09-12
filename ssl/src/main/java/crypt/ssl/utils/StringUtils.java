package crypt.ssl.utils;

public abstract class StringUtils {

    private StringUtils() {
    }

    public static boolean isEmpty(String value) {
        return value == null || value.isEmpty();
    }
}
