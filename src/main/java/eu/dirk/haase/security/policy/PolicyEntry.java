package eu.dirk.haase.security.policy;

import java.security.*;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class PolicyEntry {

    private CodeSource codeSource; // codebase + cert gained from signedby
    private boolean debug = false;
    // this is only for debug
    private boolean grant;
    private boolean neverImplies = false;
    private Permissions permissions;
    private List<Principal> principals;

    /**
     * Constructor of ProgradePolicyEntry.
     *
     * @param grant true if this policy entry represent grant entry, false if entry represent deny entry
     * @param debug true for writing debug informations, false otherwise
     */
    public PolicyEntry(boolean grant, boolean debug) {
        principals = new ArrayList<Principal>();
        permissions = new Permissions();
        this.grant = grant;
        this.debug = debug;
    }

    /**
     * Method for adding Permission to this ProgradePolicyEntry.
     *
     * @param permission Permission for adding
     */
    public void addPermission(Permission permission) {
        permissions.add(permission);
    }

    /**
     * Method for adding principal (represent by ProgradePrincipal) to this ProgradePolicyEntry.
     *
     * @param principal principal for adding
     */
    public void addPrincipal(Principal principal) {
        principals.add(principal);
    }

    /**
     * Method for determining whether this ProgradePolicyEntry implies given permission.
     *
     * @param pd         active ProtectionDomain to test
     * @param permission Permission which need to be determined
     * @return true if ProgradePolicyEntry implies given Permission, false otherwise
     */
    public boolean implies(ProtectionDomain pd, Permission permission) {

        if (neverImplies) {
            if (debug) {
                PolicyDebugger.log("This entry never imply anything.");
            }
            return false;
        }

        // codesource
        if (codeSource != null && pd.getCodeSource() != null) {
            if (debug) {
                PolicyDebugger.log("Evaluate codesource...");
                PolicyDebugger.log("      Policy codesource: " + codeSource.toString());
                PolicyDebugger.log("      Active codesource: " + pd.getCodeSource().toString());
            }
            if (!codeSource.implies(pd.getCodeSource())) {
                if (debug) {
                    PolicyDebugger.log("Evaluation (codesource) failed.");
                }
                return false;
            }
        }

        // principals
        if (!principals.isEmpty()) {
            if (debug) {
                PolicyDebugger.log("Evaluate principals...");
            }
            java.security.Principal[] pdPrincipals = pd.getPrincipals();
            if (pdPrincipals == null || pdPrincipals.length == 0) {
                if (debug) {
                    PolicyDebugger.log("Evaluation (principals) failed. There is no active principals.");
                }
                return false;
            }
            if (debug) {
                PolicyDebugger.log("Policy principals:");
                for (Principal principal : principals) {
                    PolicyDebugger.log("      " + principal.toString());
                }
                PolicyDebugger.log("Active principals:");
                if (pdPrincipals.length == 0) {
                    PolicyDebugger.log("      none");
                }
                for (int i = 0; i < pdPrincipals.length; i++) {
                    java.security.Principal principal = pdPrincipals[i];
                    PolicyDebugger.log("      " + principal.toString());
                }
            }

            for (Principal principal : principals) {
                boolean contain = false;
                for (int i = 0; i < pdPrincipals.length; i++) {
                    if (principal.hasWildcardClassName()) {
                        contain = true;
                        break;
                    }
                    java.security.Principal pdPrincipal = pdPrincipals[i];
                    if (pdPrincipal.getClass().getName().equals(principal.getClassName())) {
                        if (principal.hasWildcardPrincipal()) {
                            contain = true;
                            break;
                        }
                        if (pdPrincipal.getName().equals(principal.getPrincipalName())) {
                            contain = true;
                            break;
                        }
                    }
                }
                if (!contain) {
                    if (debug) {
                        PolicyDebugger.log("Evaluation (principals) failed.");
                    }
                    return false;
                }
            }
        }

        // permissions
        if (debug) {
            PolicyDebugger.log("Evaluation codesource/principals passed.");
            String grantOrDeny = (grant) ? "granting" : "denying";
            Enumeration<Permission> elements = permissions.elements();
            while (elements.hasMoreElements()) {
                Permission nextElement = elements.nextElement();
                PolicyDebugger.log("      " + grantOrDeny + " " + nextElement.toString());
            }
        }

        boolean toReturn = permissions.implies(permission);
        if (debug) {
            if (toReturn) {
                PolicyDebugger.log("Needed permission found in this entry.");
            } else {
                PolicyDebugger.log("Needed permission wasn't found in this entry.");
            }
        }
        return toReturn;
    }

    /**
     * Setter of CodeSource of policy entry.
     *
     * @param codeSource CodeSource of policy entry
     */
    public void setCodeSource(CodeSource codeSource) {
        this.codeSource = codeSource;
    }

    /**
     * Method for setting that this ProgradePolicyEntry never implies any Permission.
     *
     * @param neverImplies true for set that this entry never implies any Permission, false otherwise
     */
    public void setNeverImplies(boolean neverImplies) {
        this.neverImplies = neverImplies;
    }
}
