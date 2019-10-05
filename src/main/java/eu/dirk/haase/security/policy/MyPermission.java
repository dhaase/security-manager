package eu.dirk.haase.security.policy;

import java.security.BasicPermission;
import java.security.Permission;

public class MyPermission extends BasicPermission {
    /**
     * Constructs a permission with the specified name.
     *
     * @param name name of the Permission object being created.
     */
    public MyPermission(String name) {
        super(name);
        System.out.println("create: " + this);
    }

    @Override
    public boolean implies(Permission permission) {
        System.out.println(">>>>>> " + permission);
        return false;
    }


}
