package eu.dirk.haase.security.policy;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;

class SecurityActions {

    /**
     * Returns a security property value using the specified <code>key</code>.
     *
     * @param key
     * @return
     * @see Security#getProperty(String)
     */
    static String getSecurityProperty(final String key) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged((PrivilegedAction<String>) () -> Security.getProperty(key));
        } else {
            return Security.getProperty(key);
        }
    }

    /**
     * Returns a system property value using the specified <code>key</code>.
     *
     * @param key
     * @return
     */
    static String getSystemProperty(final String key) {
        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            return AccessController.doPrivileged((PrivilegedAction<String>) () -> System.getProperty(key));
        } else {
            return System.getProperty(key);
        }
    }
}