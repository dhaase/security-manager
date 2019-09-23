package eu.dirk.haase.security;

import eu.dirk.haase.security.manager.FinalSecurityManager;
import eu.dirk.haase.security.policy.FinalPolicy;

import java.io.File;
import java.io.Reader;
import java.io.StringReader;
import java.security.Policy;

public class Main {

    public static void main(String[] args) {
        String policyStr = "";
        policyStr += "grant {";
        policyStr += "    permission java.security.AllPermission;";
        policyStr += "};";
        Reader reader = new StringReader(policyStr);
        Policy policy = new FinalPolicy(reader);
        Policy.setPolicy(policy);
        System.setSecurityManager(new FinalSecurityManager());
        Policy i;
        File file = new File("./my-test-file");
        file.delete();
    }

}
