/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.log4j;

import java.io.StringReader;
import java.util.Properties;
import java.util.Vector;

import junit.framework.TestCase;

import org.apache.log4j.xml.DOMConfigurator;

/**
 * Regression tests for the NTEventLogAppender DLL preloading issue.
 *
 * <p>NTEventLogAppender loaded its native library through
 * <code>System.loadLibrary("NTEventLogAppender...")</code> in a static
 * initializer. On Windows the library search includes the current working
 * directory, so a planted NTEventLogAppender*.dll was executed as soon as a
 * configuration referenced the appender. The appender has been removed; these
 * tests make sure that no configuration path can trigger that native library
 * lookup anymore.
 */
public class NTEventLogAppenderRemovedTest extends TestCase {

    private static final String NT_APPENDER =
            "org.apache.log4j.nt.NTEventLogAppender";

    private static final String NT_LIBRARY = "NTEventLogAppender";

    private SecurityManager previousSecurityManager;

    private LoadLibraryRecorder recorder;

    public NTEventLogAppenderRemovedTest(final String name) {
        super(name);
    }

    protected void setUp() {
        previousSecurityManager = System.getSecurityManager();
        recorder = new LoadLibraryRecorder();
        System.setSecurityManager(recorder);
    }

    protected void tearDown() {
        System.setSecurityManager(previousSecurityManager);
        LogManager.resetConfiguration();
    }

    /**
     * The appender class, whose static initializer loaded the DLL,
     * must not be loadable anymore.
     */
    public void testAppenderClassIsNotAvailable() {
        try {
            Class.forName(NT_APPENDER);
            fail(NT_APPENDER + " must not be available");
        } catch (ClassNotFoundException expected) {
        }
        assertNoNativeLibraryLoad();
    }

    /**
     * A properties configuration naming the appender must not trigger
     * a native library lookup.
     */
    public void testPropertyConfiguratorDoesNotLoadNativeLibrary() {
        Properties props = new Properties();
        props.setProperty("log4j.rootLogger", "DEBUG, NT");
        props.setProperty("log4j.appender.NT", NT_APPENDER);
        props.setProperty("log4j.appender.NT.Source", "Log4j");
        props.setProperty("log4j.appender.NT.layout",
                "org.apache.log4j.SimpleLayout");
        PropertyConfigurator.configure(props);

        Logger.getLogger(NTEventLogAppenderRemovedTest.class).error("Message");

        assertNull(Logger.getRootLogger().getAppender("NT"));
        assertNoNativeLibraryLoad();
    }

    /**
     * An XML configuration naming the appender must not trigger
     * a native library lookup.
     */
    public void testDOMConfiguratorDoesNotLoadNativeLibrary() {
        String xml =
            "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
            + "<!DOCTYPE log4j:configuration SYSTEM \"log4j.dtd\">\n"
            + "<log4j:configuration xmlns:log4j=\"http://jakarta.apache.org/log4j/\">\n"
            + "  <appender name=\"NT\" class=\"" + NT_APPENDER + "\">\n"
            + "    <param name=\"Source\" value=\"Log4j\"/>\n"
            + "    <layout class=\"org.apache.log4j.SimpleLayout\"/>\n"
            + "  </appender>\n"
            + "  <root>\n"
            + "    <level value=\"debug\"/>\n"
            + "    <appender-ref ref=\"NT\"/>\n"
            + "  </root>\n"
            + "</log4j:configuration>\n";
        new DOMConfigurator().doConfigure(new StringReader(xml),
                LogManager.getLoggerRepository());

        Logger.getLogger(NTEventLogAppenderRemovedTest.class).error("Message");

        assertNull(Logger.getRootLogger().getAppender("NT"));
        assertNoNativeLibraryLoad();
    }

    private void assertNoNativeLibraryLoad() {
        Vector libraries = recorder.getLibraries();
        for (int i = 0; i < libraries.size(); i++) {
            String library = (String) libraries.elementAt(i);
            if (library.indexOf(NT_LIBRARY) != -1) {
                fail("native library lookup attempted: " + library);
            }
        }
    }

    /**
     * Permissive security manager recording every native library
     * load request (System.loadLibrary calls checkLink first).
     */
    private static final class LoadLibraryRecorder extends SecurityManager {
        private final Vector libraries = new Vector();

        public void checkPermission(final java.security.Permission perm) {
        }

        public void checkPermission(final java.security.Permission perm,
                                    final Object context) {
        }

        public void checkLink(final String lib) {
            synchronized (libraries) {
                libraries.addElement(lib);
            }
        }

        Vector getLibraries() {
            synchronized (libraries) {
                return (Vector) libraries.clone();
            }
        }
    }
}
