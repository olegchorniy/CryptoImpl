package crypt.ssl.utils;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;

public abstract class TlsEnumUtils {

    private TlsEnumUtils() {
    }

    public static <E extends Enum<E> & TlsEnum> void writeEnum(E constant, OutputStream out) throws IOException {
        IO.writeInt(out, constant.getValue(), getSize(constant.getDeclaringClass()));
    }

    public static <E extends Enum<E> & TlsEnum> E readEnum(Class<E> enumClass, InputStream in) throws IOException {
        int size = getSize(enumClass);
        int enumValue = IO.readInt(in, size);

        return getEnumConstant(enumClass, enumValue);
    }

    public static <E extends Enum<E> & TlsEnum> E getEnumConstant(Class<E> enumClass, int value) {

        for (E e : enumClass.getEnumConstants()) {
            if (e.getValue() == value) {
                return e;
            }
        }

        throw new IllegalArgumentException(enumClass.getSimpleName() + " has no constant with value '" + value + "'");
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
}
