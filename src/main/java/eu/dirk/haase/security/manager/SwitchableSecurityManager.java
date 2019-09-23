package eu.dirk.haase.security.manager;

import java.security.AccessControlContext;
import java.security.Permission;
import java.util.concurrent.atomic.AtomicBoolean;

abstract class SwitchableSecurityManager extends AbstractSecurityManager implements CheckerRunnable {

    private final AtomicBoolean defaultCheckFlag;

    private final ThreadLocal<AccessContext> threadLocalAccessContext;

    public SwitchableSecurityManager() {
        this.defaultCheckFlag = new AtomicBoolean(true);
        this.threadLocalAccessContext = new ThreadLocal<>();
    }

    @Override
    final void checkPermissionInternal(Permission perm, AccessControlContext context) {
        final CheckerRunnable checker = this.threadLocalAccessContext.get();
        checkPermissionInternal(perm, context, (checker == null ? this : checker));
    }

    abstract void checkPermissionInternal(Permission perm, AccessControlContext context, CheckerRunnable runnable);

    @Override
    final boolean doCheck() {
        final AccessContext ac = this.threadLocalAccessContext.get();
        return (ac != null ? ac.checking : defaultCheckFlag.get());
    }

    @Override
    public void runCheck(final Runnable checkRunnable) {
        checkRunnable.run();
    }

    public final void switchCheckDefault(final boolean doCheckFlag) {
        this.defaultCheckFlag.set(doCheckFlag);
    }

    public final void switchCheckOnCurrentThread(final boolean doCheckFlag) {
        final AccessContext ac = new AccessContext();
        ac.checking = doCheckFlag;
        this.threadLocalAccessContext.set(ac);
    }

}
