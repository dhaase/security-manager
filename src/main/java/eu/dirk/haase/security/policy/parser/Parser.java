package eu.dirk.haase.security.policy.parser;


import eu.dirk.haase.security.policy.Priority;
import eu.dirk.haase.security.policy.PolicyDebugger;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class Parser {

    private boolean debug = false;
    private List<ParsedPolicyEntry> denyEntries;
    private List<ParsedPolicyEntry> grantEntries;
    private ParsedKeystoreEntry keystoreEntry;
    private String keystorePasswordURL;
    private int lookahead;
    private Priority priority;
    private StreamTokenizer st;

    /**
     * Constructor with predefined debug to false.
     */
    public Parser() {
        this(false);
    }

    /**
     * Constructor of Parser.
     *
     * @param debug true for writing debug informations.
     */
    public Parser(boolean debug) {
        this.debug = debug;
    }

    /**
     * Parse content of text policy file to ParsedPolicy object which represent this policy.
     *
     * @param file text file with policy file
     * @return parsed policy file which is represented by ParsedPolicy
     * @throws throw Exception when any problem occurred during parsing file (file doesn't exist, incompatible policy file etc.)
     */
    public ParsedPolicy parse(File file) throws Exception {
        if (file == null || !file.exists()) {
            if (debug) {
                if (file == null) {
                    PolicyDebugger.log("Given File is null");
                } else {
                    if (!file.exists()) {
                        PolicyDebugger.log("Policy file " + file.getCanonicalPath() + " doesn't exists.");
                    }
                }
            }
            throw new Exception("ER007: File with policy doesn't exists!");
        }

        if (debug) {
            PolicyDebugger.log("Parsing policy " + file.getCanonicalPath());
        }

        final InputStreamReader reader = new InputStreamReader(new FileInputStream(file), "UTF-8");
        try {
            return parse(reader);
        } finally {
            reader.close();
        }
    }

    /**
     * Parse policy from given reader to a ParsedPolicy object.
     *
     * @param reader reader which provides policy content
     * @return parsed policy file which is represented by ParsedPolicy
     * @throws throw Exception when any problem occurred during parsing file (file doesn't exist, incompatible policy file etc.)
     */
    public ParsedPolicy parse(Reader reader) throws Exception {
        BufferedReader br = new BufferedReader(reader);
        st = new StreamTokenizer(br);

        st.resetSyntax();
        st.wordChars('a', 'z');
        st.wordChars('A', 'Z');
        st.wordChars('.', '.');
        st.wordChars('0', '9');
        st.wordChars('_', '_');
        st.wordChars('$', '$');
        st.wordChars(128 + 32, 255);
        st.whitespaceChars(0, ' ');
        st.commentChar('/');
        st.quoteChar('\'');
        st.quoteChar('"');
        st.lowerCaseMode(false);
        st.ordinaryChar('/');
        st.slashSlashComments(true);
        st.slashStarComments(true);

        grantEntries = new ArrayList<ParsedPolicyEntry>();
        denyEntries = new ArrayList<ParsedPolicyEntry>();

        lookahead = st.nextToken();

        while (lookahead != StreamTokenizer.TT_EOF) {
            switch (lookahead) {
                case StreamTokenizer.TT_WORD:
                    String readWord = st.sval;
                    if (readWord.toLowerCase().equals("grant")) {
                        parseGrantOrDenyEntry(true);
                    } else {
                        if (readWord.toLowerCase().equals("deny")) {
                            parseGrantOrDenyEntry(false);
                        } else {
                            if (readWord.toLowerCase().equals("keystore")) {
                                parseKeystore();
                            } else {
                                if (readWord.toLowerCase().equals("keystorepasswordurl")) {
                                    parseKeystorePassword();
                                } else {
                                    if (readWord.toLowerCase().equals("priority")) {
                                        parsePriority();
                                    } else {
                                        throw new Exception(
                                                "ER008: grant, deny, keystore or keystorePasswordURL expected, but was ["
                                                        + readWord + "]");
                                    }
                                }
                            }
                        }
                    }
                    break;
                case ';':
                    break;
                default:
                    throw new Exception("ER009: some of keyword expected!");

            }
            lookahead = st.nextToken();
        }

        if (debug) {
            for (ParsedPolicyEntry p : grantEntries) {
                PolicyDebugger.log("Adding following grant entry:");
                PolicyDebugger.log(p.toString());
            }

            for (ParsedPolicyEntry p : denyEntries) {
                PolicyDebugger.log("Adding following deny entry:");
                PolicyDebugger.log(p.toString());
            }

            if (keystoreEntry == null) {
                PolicyDebugger.log("KeyStore isn't set");
            } else {
                PolicyDebugger.log("Adding following keystore:");
                PolicyDebugger.log(keystoreEntry.toString());
            }

            if (keystorePasswordURL == null) {
                PolicyDebugger.log("KeystorePasswordURL isn't set");
            } else {
                PolicyDebugger.log("Adding following keystorePasswordURL: " + keystorePasswordURL);
            }
            PolicyDebugger.log("Adding following priority: " + priority + "\n");
        }

        return new ParsedPolicy(grantEntries, denyEntries, keystoreEntry, keystorePasswordURL, priority);
    }

    /**
     * Private method for parsing policy (grant or deny) entry.
     *
     * @param grantOrDeny true for grant entry, false for deny entry
     * @throws throws Exception when any problem occurred during parsing policy entry
     */
    private void parseGrantOrDenyEntry(boolean grantOrDeny) throws Exception {
        ParsedPolicyEntry policyEntry = new ParsedPolicyEntry();
        boolean nextPartExpected = true; // next part means permissions section
        lookahead = st.nextToken();
        while (lookahead != '{') {
            switch (lookahead) {
                case StreamTokenizer.TT_WORD:
                    String readWord = st.sval;
                    nextPartExpected = true;
                    if (readWord.toLowerCase().equals("codebase")) {
                        if (policyEntry.getCodebase() != null) {
                            throw new Exception("ER010: More codebase expression!");
                        }
                        lookahead = st.nextToken();
                        if (lookahead == '\"') {
                            policyEntry.setCodebase(st.sval);
                        } else {
                            throw new Exception("ER011: Codebase parameter have to start with \".");
                        }
                    } else {
                        if (readWord.toLowerCase().equals("signedby")) {
                            if (policyEntry.getSignedBy() != null) {
                                throw new Exception("ER012: More signedBy expression!");
                            }
                            lookahead = st.nextToken();
                            if (lookahead == '\"') {
                                policyEntry.setSignedBy(st.sval);
                            } else {
                                throw new Exception("ER013: SignedBy parameter have to start with \".");
                            }
                        } else {
                            if (readWord.toLowerCase().equals("principal")) {
                                policyEntry.addPrincipal(parsePrincipal());
                            } else {
                                throw new Exception("ER014: Codebase, signedBy or principal expected.");
                            }
                        }

                    }
                    break;
                case ',':
                    if (!nextPartExpected) {
                        throw new Exception("ER015: Some of keywords expected, but there was [,,] instead.");
                    }
                    nextPartExpected = false;
                    break;
                default:
                    throw new Exception("ER016: Some of keywords or '{' expected.");
            }
            lookahead = st.nextToken();
        }
        if (!nextPartExpected) {
            throw new Exception("ER017: Some of keywords expected, but there was [,{] instead.");
        }
        lookahead = st.nextToken();
        while (lookahead != '}') {
            String readPermission = st.sval;
            if (readPermission.toLowerCase().equals("permission")) {
                policyEntry.addPermission(parsePermission());
            }
            lookahead = st.nextToken();
        }

        if (grantOrDeny) {
            grantEntries.add(policyEntry);
        } else {
            denyEntries.add(policyEntry);
        }

    }

    /**
     * Private method for parsing keystore entry.
     *
     * @throws throws Exception when any problem occurred during parsing keystore entry
     */
    private void parseKeystore() throws Exception {
        String tempKeystoreURL = null;
        String tempKeystoreType = null;
        String tempKeystoreProvider = null;
        lookahead = st.nextToken();
        if (lookahead == '\"') {
            tempKeystoreURL = st.sval;
        } else {
            throw new Exception("ER029: [\"keystore_URL\"] expected.");
        }

        lookahead = st.nextToken();
        if (lookahead == ',') {
            lookahead = st.nextToken();
            if (lookahead == '\"') {
                tempKeystoreType = st.sval;
            } else {
                throw new Exception("ER030: [\"keystore_type\"] expected.");
            }
            lookahead = st.nextToken();
            if (lookahead == ',') {
                lookahead = st.nextToken();
                if (lookahead == '\"') {
                    tempKeystoreProvider = st.sval;
                } else {
                    throw new Exception("ER031: [\"keystore_provider\"] expected.");
                }
                lookahead = st.nextToken();
            }
        }

        if (lookahead == ';') {
            if (keystoreEntry == null) {
                keystoreEntry = new ParsedKeystoreEntry(tempKeystoreURL, tempKeystoreType, tempKeystoreProvider);
            }
        } else {
            throw new Exception("ER032: [;] expected at the end of keystore entry.");
        }
    }

    /**
     * Private method for parsing keystorePasswordURL entry.
     *
     * @throws throws Exception when any problem occurred during parsing keystorePasswordURL entry
     */
    private void parseKeystorePassword() throws Exception {
        lookahead = st.nextToken();
        if (lookahead == '\"') {
            if (keystorePasswordURL == null) {
                keystorePasswordURL = st.sval;
            }
        } else {
            throw new Exception("ER033: [\"keystore_password\"] expected.");
        }
        lookahead = st.nextToken();
        if (lookahead == ';') {
            return;
        } else {
            throw new Exception("ER034: [;] expected at the end of keystorePasswordURL entry.");
        }
    }

    /**
     * Private method for parsing permission part of policy entry.
     *
     * @return parsed permission part of policy entry
     * @throws throws Exception when any problem occurred during parsing permission
     */
    private ParsedPermission parsePermission() throws Exception {
        ParsedPermission permission = new ParsedPermission();
        lookahead = st.nextToken();
        if (lookahead == StreamTokenizer.TT_WORD) {
            permission.setPermissionType(st.sval);
        } else {
            throw new Exception("ER021: Permission type expected.");
        }

        lookahead = st.nextToken();
        if (lookahead == '\"') {
            permission.setPermissionName(st.sval);
        } else {
            // java.security.AllPermission possibility
            if (lookahead == ';') {
                return permission;
            }
            throw new Exception("ER022: Permission name or or [;] expected.");
        }

        lookahead = st.nextToken();
        if (lookahead == ',') {
            lookahead = st.nextToken();
            boolean shouldBeSigned = false;

            if (lookahead == '\"') {
                String actionsWords = st.sval;
                permission.setActions(actionsWords);

                lookahead = st.nextToken();
                switch (lookahead) {
                    case ',':
                        shouldBeSigned = true;
                        break;
                    case ';':
                        return permission;
                    default:
                        throw new Exception("ER023: Unexpected symbol, expected [,] or [;].");
                }
                lookahead = st.nextToken();
            }

            if (lookahead == StreamTokenizer.TT_WORD) {
                String signedByWord = st.sval;
                if (!signedByWord.toLowerCase().equals("signedby")) {
                    throw new Exception("ER024: [signedBy] expected but was [" + signedByWord + "].");
                }
            } else if (shouldBeSigned) {
                throw new Exception("ER025: [signedBy] expected after [,].");
            } else {
                throw new Exception("ER026: Actions or [signedBy] expected after [,].");
            }
            lookahead = st.nextToken();
            if (lookahead == '\"') {
                permission.setSignedBy(st.sval);
            } else {
                throw new Exception("ER027: signedBy attribute expected.");
            }
            lookahead = st.nextToken();
        }

        if (lookahead == ';') {
            return permission;
        } else {
            throw new Exception("ER028: [;] expected.");
        }

    }

    /**
     * Private method for parsing principal part of policy entry.
     *
     * @return parsed principal part of policy entry
     * @throws throws Exception when any problem occurred during parsing principal
     */
    private ParsedPrincipal parsePrincipal() throws Exception {
        lookahead = st.nextToken();
        switch (lookahead) {
            case '*':
                lookahead = st.nextToken();
                if (lookahead == '*') {
                    return new ParsedPrincipal(null, null);
                } else {
                    throw new Exception("ER018: There have to be name wildcard after type wildcard.");
                }
            case '\"':
                return new ParsedPrincipal(st.sval);
            case StreamTokenizer.TT_WORD:
                String principalClass = st.sval;
                lookahead = st.nextToken();
                switch (lookahead) {
                    case '*':
                        return new ParsedPrincipal(principalClass, null);
                    case '\"':
                        return new ParsedPrincipal(principalClass, st.sval);
                    default:
                        throw new Exception("ER019: Principal name or * expected.");
                }
            default:
                throw new Exception("ER020: Principal type, *, or keystore alias expected.");
        }
    }

    /**
     * Private method for parsing priority entry.
     *
     * @throws throws Exception when any problem occurred during parsing priority entry
     */
    private void parsePriority() throws Exception {
        lookahead = st.nextToken();
        if (lookahead == '\"') {
            if (priority == null) {
                String pr = st.sval;
                if (pr.toLowerCase().equals("grant")) {
                    priority = Priority.GRANT;
                } else {
                    if (pr.toLowerCase().equals("deny")) {
                        priority = Priority.DENY;
                    } else {
                        throw new Exception("ER035: grant or deny priority expected.");
                    }
                }
            }
        } else {
            throw new Exception("ER036: quotes expected after priority keyword.");
        }
        lookahead = st.nextToken();
        if (lookahead == ';') {
            return;
        } else {
            throw new Exception("ER037: [;] expected at the end of priority entry.");
        }
    }
}