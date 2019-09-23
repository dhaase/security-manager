package eu.dirk.haase.security.policy.parser;

import java.util.ArrayList;
import java.util.List;

public class ParsedPolicyEntry {

    private String codebase;
    private List<ParsedPermission> permissions = new ArrayList<ParsedPermission>();
    private List<ParsedPrincipal> principals = new ArrayList<ParsedPrincipal>();
    private String signedBy;

    /**
     * Add permission from policy entry represented by ParsedPermission to this ParsedPolicyEntry.
     *
     * @param perm permission from policy entry for adding
     */
    public void addPermission(ParsedPermission perm) {
        permissions.add(perm);
    }

    /**
     * Add principal from policy entry represented by ParsedPrincipal to this ParsedPolicyEntry.
     *
     * @param principal principal from policy entry for adding
     */
    public void addPrincipal(ParsedPrincipal principal) {
        principals.add(principal);
    }

    /**
     * Getter of codebase from policy entry.
     *
     * @return codebase from policy entry
     */
    public String getCodebase() {
        return codebase;
    }

    /**
     * Setter of codebase from policy entry.
     *
     * @param codebase codebase from policy entry
     */
    public void setCodebase(String codebase) {
        this.codebase = codebase;
    }

    /**
     * Getter of permissions from policy entry which are represented by list of ParsedPermission.
     *
     * @return list of ParsedPermission from policy entry
     */
    public List<ParsedPermission> getPermissions() {
        return permissions;
    }

    /**
     * Getter of principals from policy entry which are represented by list of ParsedPrincipal.
     *
     * @return list of ParsedPrincipal from policy entry
     */
    public List<ParsedPrincipal> getPrincipals() {
        return principals;
    }

    /**
     * Getter of signedBy from policy entry.
     *
     * @return signedBy from policy entry
     */
    public String getSignedBy() {
        return signedBy;
    }

    /**
     * Setter of signedBy from policy entry.
     *
     * @param signedBy signedBy from policy entry
     */
    public void setSignedBy(String signedBy) {
        this.signedBy = signedBy;
    }

    @Override
    public String toString() {
        String toReturn = "";
        String toReturnCodebase = (codebase == null) ? "undefined" : codebase;
        String toReturnSignedBy = (signedBy == null) ? "undefined" : signedBy;
        toReturn += "Codebase: " + toReturnCodebase + ", Signed By: " + toReturnSignedBy + ", Principals: { ";
        int counter = 0;
        for (ParsedPrincipal p : principals) {
            if (counter != 0) {
                toReturn += ", ";
            }
            toReturn += p.toString();
            counter++;
        }
        if (principals.isEmpty()) {
            toReturn += "undefined";
        }
        toReturn += " }\n";
        toReturn += "permissions: \n";
        for (ParsedPermission p : permissions) {
            toReturn += "  " + p.toString();
        }
        return toReturn;
    }
}