package eu.dirk.haase.security.loaded;

import java.io.FilePermission;

public class MyResource implements Runnable {

    public void run() {
        SecurityManager sm = System.getSecurityManager();
        sm.checkPermission(new FilePermission("/my-test", "read"));
    }

}
