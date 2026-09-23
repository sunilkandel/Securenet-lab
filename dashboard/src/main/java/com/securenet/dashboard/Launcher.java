package com.securenet.dashboard;

/**
 * Plain entry point for IDEs and "java -cp" runs.
 *
 * <p>Launching a class that extends Application directly from the classpath
 * fails with "JavaFX runtime components are missing"; going through a
 * class that does not extend it avoids that check.
 */
public final class Launcher {
    private Launcher() {
    }

    public static void main(String[] args) {
        App.main(args);
    }
}
