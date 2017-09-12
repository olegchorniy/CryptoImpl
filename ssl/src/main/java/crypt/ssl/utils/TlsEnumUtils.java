package crypt.ssl.utils;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;

public abstract class TlsEnumUtils {

    private TlsEnumUtils() {
    }

    public static <E extends Enum<E> & TlsEnum> E getEnumConstant(Class<E> enumClass, int value) {

        for (E e : enumClass.getEnumConstants()) {
            if (e.getValue() == value) {
                return e;
            }
        }

        throw new IllegalArgumentException(enumClass.getSimpleName() + " has no constant with value '" + value + "'");
    }

    public static <E extends Enum<E> & TlsEnum> int getSize(Class<E> enumClass) {
        Size sizeAnnotation = enumClass.getDeclaredAnnotation(Size.class);

        if (sizeAnnotation == null) {
            throw new IllegalStateException("'Size' annotation is not found on the 'value' field");
        }

        return sizeAnnotation.value();
    }
}
