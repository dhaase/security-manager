package eu.dirk.haase.security.manager;

import java.security.AccessControlContext;
import java.security.Permission;

public interface ExtendedSecurityManager {

    void switchCheckDefault(final boolean doCheckFlag);

    void switchCheckOnCurrentThread(final boolean doCheckFlag);

    boolean testPermission(final Permission perm, final AccessControlContext context);

    boolean testPermission(final Permission perm);

}
