package eu.dirk.haase.security;

import eu.dirk.haase.security.manager.FinalSecurityManager;
import eu.dirk.haase.security.policy.FinalPolicy;

import java.io.File;
import java.security.AllPermission;
import java.security.Policy;
import java.security.SecureClassLoader;
import java.util.Enumeration;

public class Main {

    public static void main(String[] args) throws ClassNotFoundException, IllegalAccessException, InstantiationException {

        String policyStr = "";
        policyStr += "grant codeBase \"file:/C:/Users/Dirk/Documents/java/security-manager/target/classes/\" {";
        policyStr += "    permission java.security.AllPermission;";
        policyStr += "};";
        policyStr += "deny codeBase \"file:/C:/Users/Dirk/Documents/java/security-manager/target/classes/\" {";
        policyStr += "    permission java.lang.RuntimePermission \"getProtectionDomain\";";
        policyStr += "};";
        Policy policy = new FinalPolicy(policyStr);
        Policy.setPolicy(policy);

        final SecurityManager securityManager = new FinalSecurityManager(policy);
        System.setSecurityManager(securityManager);

        File file = new File("./my-test-file");
        file.delete();

        //file.getClass().getProtectionDomain();

//
//        Class<?> aClass = Class.forName("org.springframework.core.annotation.AnnotationUtils");
//        Enumeration<?> en = aClass.getProtectionDomain().getPermissions().elements();
//        while (en.hasMoreElements()) {
//            System.out.println(en.nextElement());
//        }
//
//        System.out.println(aClass.getProtectionDomain().getPermissions().getClass());
//
//        ExtendedSecurityManager extendedSecurityManager = (ExtendedSecurityManager) System.getSecurityManager();
//        extendedSecurityManager.switchCheckDefault(false);
//        Policy.setPolicy(policy);


    }

}
