package eu.dirk.haase.security.policy.parser;

public class ParsedPrincipal {

    private String alias = "";
    private boolean classWildcard = false;
    private boolean isAlias = false;
    private boolean nameWildcard = false;
    private String principalClass = "";
    private String principalName = "";

    /**
     * Constructor for principal from policy file representing by alias in keystore entry.
     *
     * @param alias alias of principal in keystore entry
     */
    public ParsedPrincipal(String alias) {
        this.alias = alias;
        isAlias = true;
    }

    /**
     * Constructor for classic type of principal in policy file.
     *
     * @param principalClass name of Principal class or null for wildcard which means every principal class
     * @param principalName  name of principal or null for wildcard which means every principal of given Principal class
     */
    public ParsedPrincipal(String principalClass, String principalName) {
        if (principalClass != null) {
            this.principalClass = principalClass;
        } else {
            classWildcard = true;
        }
        if (principalName != null) {
            this.principalName = principalName;
        } else {
            nameWildcard = true;
        }
    }

    /**
     * Getter of principal alias in keystore from principal entry.
     *
     * @return principal alias in keystore from principal entry
     */
    public String getAlias() {
        return alias;
    }

    /**
     * Getter of Principal class name from principal entry.
     *
     * @return name of Principal class name from principal entry
     */
    public String getPrincipalClass() {
        return principalClass;
    }

    /**
     * Getter of principal name from principal entry.
     *
     * @return name of principal from principal entry
     */
    public String getPrincipalName() {
        return principalName;
    }

    /**
     * Method for determining whether principal entry has alias for keystore.
     *
     * @return true if principal entry has alias for keystore or false if it doesn't have it
     */
    public boolean hasAlias() {
        return isAlias;
    }

    /**
     * Method for determining whether principal entry has wildcard for class name.
     *
     * @return true if principal entry has wildcard for class name or false if it doesn't have it
     */
    public boolean hasClassWildcard() {
        return classWildcard;
    }

    /**
     * Method for determining whether principal entry has wildcard for principal name.
     *
     * @return true if principal entry has wildcard for principal name or false if it doesn't have it
     */
    public boolean hasNameWildcard() {
        return nameWildcard;
    }

    @Override
    public String toString() {
        String toReturn = "";
        String toReturnClass = (classWildcard) ? "*" : principalClass;
        String toReturnName = (nameWildcard) ? "*" : principalName;
        if (isAlias) {
            toReturn += "\"" + alias + "\"";
        } else {
            toReturn += toReturnClass + "/" + toReturnName;
        }
        return toReturn;
    }
}