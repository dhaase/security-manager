package eu.dirk.haase.security.manager;

import eu.dirk.haase.security.policy.MyPermission;

import javax.security.auth.SubjectDomainCombiner;
import java.lang.reflect.Field;
import java.security.*;
import java.util.Arrays;
import java.util.Enumeration;

import static java.security.AccessController.doPrivileged;

public final class FinalSecurityManager extends SwitchableSecurityManager implements ExtendedSecurityManager {

    private static final Field PD_STACK;

    static {
        PD_STACK = doPrivileged(new GetAccessibleDeclaredFieldAction(AccessControlContext.class, "context"));
    }

    private final Policy policy;

    public FinalSecurityManager(final Policy policy) {
        this.policy = policy;
    }

    private static ProtectionDomain[] getProtectionDomainStack(final AccessControlContext context) {
        final ProtectionDomain[] stack;
        try {
            stack = (ProtectionDomain[]) PD_STACK.get(context);
        } catch (Exception e) {
            // should be impossible
            throw new IllegalAccessError(e.getMessage());
        }
        return stack;
    }

    @Override
    final void checkPermissionInternal(final Permission perm, final AccessControlContext context, final CheckerRunnable runnable) {
        runnable.runCheck(() -> {
            System.out.println("<>>>>>< " + perm);
            if (perm instanceof MyPermission) {
                context.checkPermission(perm);
            }
//            final String msg = getFailMessageOnDeniedPermission(perm, context);
//            if (msg != null) {
//                throw new AccessControlException(msg, perm);
//            }
        });
    }

    private ProtectionDomain findAccessDenial(final Permission permission, final ProtectionDomain[] domains) {
        if (domains != null) {
            for (ProtectionDomain domain : domains) {
                if (!domain.implies(permission)) {
                //if (!policy.implies(domain, permission)) {
                    return domain;
                }
            }
        }
        return null;
    }

    private String getFailMessageOnDeniedPermission(final Permission perm, final AccessControlContext context) {
        if (perm instanceof MyPermission) {
            final ProtectionDomain[] stack = getProtectionDomainStack(context);
            if (stack != null) {
                final ProtectionDomain deniedDomain = findAccessDenial(perm, stack);
                if (deniedDomain != null) {
                    final CodeSource codeSource = deniedDomain.getCodeSource();
                    final ClassLoader classLoader = deniedDomain.getClassLoader();
                    final Principal[] principals = deniedDomain.getPrincipals();
                    String msg;
                    if ((principals == null) || (principals.length == 0)) {
                        msg = "Permission check failed (permission " +
                                perm + " in code source " +
                                codeSource + " of " +
                                classLoader + ")";
                    } else {
                        msg = "Permission check failed (permission " +
                                perm + " in code source " +
                                codeSource + " of " +
                                classLoader + ", principals " +
                                Arrays.toString(principals) + ")";
                    }
                    return msg;
                }
            }
        }
        return null;
    }

    public boolean testPermission(final Permission perm, final AccessControlContext context) {
        final String msg = getFailMessageOnDeniedPermission(perm, context);
        return (msg == null);
    }

    public boolean testPermission(final Permission perm) {
        return testPermission(perm, AccessController.getContext());
    }

}
