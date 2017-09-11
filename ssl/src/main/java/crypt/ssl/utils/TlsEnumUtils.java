package crypt.ssl.utils;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;

import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.Field;

public abstract class TlsEnumUtils {

    private TlsEnumUtils() {
    }

    public static <E extends Enum<E> & TlsEnum> void serialize(E constant, OutputStream out) throws IOException {
        IO.writeInt(out, constant.getValue(), getSize(constant.getDeclaringClass()));
    }

    private static <E extends Enum<E> & TlsEnum> int getSize(Class<E> enumClass) {
        try {
            Field valueField = enumClass.getDeclaredField("value");
            Size sizeAnnotation = valueField.getAnnotation(Size.class);

            if (sizeAnnotation == null) {
                throw new IllegalStateException("'Size' annotation is not found on the 'value' field");
            }

            return sizeAnnotation.value();
        } catch (NoSuchFieldException e) {
            throw new RuntimeException("'value' field is not found in the declaring Enum class", e);
        }
    }

    public static <E extends Enum<E> & TlsEnum> E tlsEnumConstant(Class<E> enumClass, int value) {

        for (E e : enumClass.getEnumConstants()) {
            if (e.getValue() == value) {
                return e;
            }
        }

        throw new IllegalArgumentException(enumClass.getSimpleName() + " has no constant with value '" + value + "'");
    }
}
