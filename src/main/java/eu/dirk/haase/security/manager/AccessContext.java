package eu.dirk.haase.security.manager;

class AccessContext implements CheckerRunnable {

    boolean checking = true;
    boolean entered = false;

    @Override
    public void runCheck(final Runnable checkRunnable) {
        if (!entered) {
            entered = true;
            try {
                checkRunnable.run();
            } finally {
                entered = true;
            }
        }
    }
}

