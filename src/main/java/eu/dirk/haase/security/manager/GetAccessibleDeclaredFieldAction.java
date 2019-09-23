package eu.dirk.haase.security.manager;

import java.lang.reflect.Field;
import java.security.PrivilegedAction;

final class GetAccessibleDeclaredFieldAction implements PrivilegedAction<Field> {
    private final Class<?> clazz;
    private final String fieldName;

    /**
     * Construct a new instance.
     *
     * @param clazz     the class to search
     * @param fieldName the field name to search for
     */
    public GetAccessibleDeclaredFieldAction(final Class<?> clazz, final String fieldName) {
        this.clazz = clazz;
        this.fieldName = fieldName;
    }

    public Field run() {
        final Field field;
        try {
            field = clazz.getDeclaredField(fieldName);
        } catch (NoSuchFieldException e) {
            throw new NoSuchFieldError(e.getMessage());
        }
        field.setAccessible(true);
        return field;
    }
}