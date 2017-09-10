package crypt.ssl.messages;


public interface TlsEnum {

    int getValue();

    static <E extends Enum<E> & TlsEnum> E tlsEnumConstant(Class<E> enumClass, int value) {

        for (E e : enumClass.getEnumConstants()) {
            if (e.getValue() == value) {
                return e;
            }
        }

        throw new IllegalArgumentException(enumClass.getSimpleName() + " has no constant with value '" + value + "'");
    }
}
