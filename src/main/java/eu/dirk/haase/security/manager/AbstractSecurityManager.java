package eu.dirk.haase.security.manager;

import java.io.FileDescriptor;
import java.net.InetAddress;
import java.security.AccessControlContext;
import java.security.AccessController;
import java.security.Permission;


abstract class AbstractSecurityManager extends SecurityManager {

    private static final Permission CREATE_SECURITY_MANAGER_PERMISSION = new RuntimePermission("setSecurityManager");
    private static final Permission SET_SECURITY_MANAGER_PERMISSION = new RuntimePermission("setSecurityManager");

    public AbstractSecurityManager() {
        super();
    }

    @Override
    public void checkAccept(final String host, final int port) {
        if (doCheck()) {
            super.checkAccept(host, port);
        }
    }

    @Override
    public void checkAccess(final Thread t) {
        if (doCheck()) {
            super.checkAccess(t);
        }
    }

    @Override
    public void checkAccess(final ThreadGroup g) {
        if (doCheck()) {
            super.checkAccess(g);
        }
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public void checkAwtEventQueueAccess() {
        if (doCheck()) {
            super.checkAwtEventQueueAccess();
        }
    }

    @Override
    public void checkConnect(final String host, final int port) {
        if (doCheck()) {
            super.checkConnect(host, port);
        }
    }

    @Override
    public void checkConnect(final String host, final int port, final Object context) {
        if (doCheck()) {
            super.checkConnect(host, port, context);
        }
    }

    @Override
    public void checkCreateClassLoader() {
        if (doCheck()) {
            super.checkCreateClassLoader();
        }
    }

    @Override
    public void checkDelete(final String file) {
        if (doCheck()) {
            super.checkDelete(file);
        }
    }

    @Override
    public void checkExec(final String cmd) {
        if (doCheck()) {
            super.checkExec(cmd);
        }
    }

    @Override
    public void checkExit(final int status) {
        if (doCheck()) {
            super.checkExit(status);
        }
    }

    @Override
    public void checkLink(final String lib) {
        if (doCheck()) {
            super.checkLink(lib);
        }
    }

    @Override
    public void checkListen(final int port) {
        if (doCheck()) {
            super.checkListen(port);
        }
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public void checkMemberAccess(final Class<?> clazz, final int which) {
        if (doCheck()) {
            super.checkMemberAccess(clazz, which);
        }
    }

    @Override
    public void checkMulticast(final InetAddress maddr) {
        if (doCheck()) {
            super.checkMulticast(maddr);
        }
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public void checkMulticast(final InetAddress maddr, final byte ttl) {
        if (doCheck()) {
            super.checkMulticast(maddr, ttl);
        }
    }

    @Override
    public void checkPackageAccess(final String pkg) {
        if (doCheck()) {
            super.checkPackageAccess(pkg);
        }
    }

    @Override
    public void checkPackageDefinition(final String pkg) {
        if (doCheck()) {
            super.checkPackageDefinition(pkg);
        }
    }

    @Override
    public final void checkPermission(final Permission perm) throws SecurityException {
        checkPermission(perm, AccessController.getContext());
    }

    @Override
    public final void checkPermission(final Permission perm, final Object context) throws SecurityException {
        if (context instanceof AccessControlContext) {
            checkPermission(perm, (AccessControlContext) context);
        } else {
            throw new SecurityException("Unknown Access-Control Context");
        }
    }

    public final void checkPermission(final Permission perm, final AccessControlContext context) {
        if (doCheck()) {
            if (perm.implies(SET_SECURITY_MANAGER_PERMISSION)) {
                throw new SecurityException("Security manager may not be changed");
            }
            if (perm.implies(CREATE_SECURITY_MANAGER_PERMISSION)) {
                throw new SecurityException("Security manager may not be created");
            }
            checkPermissionInternal(perm, context);
        }
    }

    void checkPermissionInternal(final Permission perm, final AccessControlContext context) {
        super.checkPermission(perm, context);
    }

    @Override
    public void checkPrintJobAccess() {
        if (doCheck()) {
            super.checkPrintJobAccess();
        }
    }

    @Override
    public void checkPropertiesAccess() {
        if (doCheck()) {
            super.checkPropertiesAccess();
        }
    }

    @Override
    public void checkPropertyAccess(final String key) {
        if (doCheck()) {
            super.checkPropertyAccess(key);
        }
    }

    @Override
    public void checkRead(final FileDescriptor fd) {
        if (doCheck()) {
            super.checkRead(fd);
        }
    }

    @Override
    public void checkRead(final String file) {
        if (doCheck()) {
            super.checkRead(file);
        }
    }

    @Override
    public void checkRead(final String file, final Object context) {
        if (doCheck()) {
            super.checkRead(file, context);
        }
    }

    @Override
    public void checkSecurityAccess(final String target) {
        if (doCheck()) {
            super.checkSecurityAccess(target);
        }
    }

    @Override
    public void checkSetFactory() {
        if (doCheck()) {
            super.checkSetFactory();
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    public void checkSystemClipboardAccess() {
        if (doCheck()) {
            super.checkSystemClipboardAccess();
        }
    }

    @Override
    @Deprecated
    @SuppressWarnings("deprecation")
    public boolean checkTopLevelWindow(final Object window) {
        if (doCheck()) {
            return super.checkTopLevelWindow(window);
        }
        return true;
    }

    @Override
    public void checkWrite(final FileDescriptor fd) {
        if (doCheck()) {
            super.checkWrite(fd);
        }
    }

    @Override
    public void checkWrite(final String file) {
        if (doCheck()) {
            super.checkWrite(file);
        }
    }

    boolean doCheck() {
        return false;
    }

}
