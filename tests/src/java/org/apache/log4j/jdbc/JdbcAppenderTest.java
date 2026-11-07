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
package org.apache.log4j.jdbc;

import junit.framework.TestCase;

import org.apache.log4j.Appender;
import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.NDC;
import org.apache.log4j.PatternLayout;
import org.apache.log4j.PropertyConfigurator;
import org.apache.log4j.VectorErrorHandler;
import org.apache.log4j.spi.ErrorCode;
import org.apache.log4j.xml.XLevel;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

public class JdbcAppenderTest extends TestCase {
    private static final String TEST_INPUT_PREFIX = "input/";

    private static final String SECURE_JDBC_REPLACEMENT =
            "org.apache.log4j.jdbc.JDBCAppender.secure_jdbc_replacement";

    private static final String DB_URL = "jdbc:h2:mem:test_db";

    private static final String INSERT_SQL =
            "insert into logs(level,location,message,message2) values('%p','%c','%m', ' %c %p %m')";

    /**
     * Logged value that, when concatenated into the SQL of INSERT_SQL, closes
     * the string literal, completes the first row and smuggles in a second
     * row; the rest of the original statement is commented out.
     */
    private static final String SQL_INJECTION_PAYLOAD = "x','y'),('I','I','I','I')--";

    // Closing the last connection to "in-memory h2" removes the database
    // So we keep the connection during the test
    // The logger opens its own connection
    Connection con;

    public JdbcAppenderTest(final String name) {
        super(name);
    }

    public void setUp() throws Exception {
        Class.forName("org.h2.Driver");
        con = DriverManager.getConnection(DB_URL);
        Statement st = con.createStatement();
        try {
            st.execute("create table logs(level varchar(100),location varchar(100),message varchar(100),message2 varchar(100))");
        } finally {
            st.close();
        }
    }

    public void tearDown() throws Exception {
        LogManager.shutdown();
        System.getProperties().remove(SECURE_JDBC_REPLACEMENT);
        MDC.remove("user");
        NDC.remove();
        con.close();
    }

    public void testJdbcInsecure() throws SQLException {
        System.setProperty(SECURE_JDBC_REPLACEMENT, "false");
        try {
            PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize1.properties");
            Appender jdbcAppender = LogManager.getRootLogger().getAppender("A");
            // Keep errors
            VectorErrorHandler errorHandler = new VectorErrorHandler();
            jdbcAppender.setErrorHandler(errorHandler);

            Logger logger = Logger.getLogger(JdbcAppenderTest.class);

            String oldThreadName = Thread.currentThread().getName();
            try {
                Thread.currentThread().setName("main");
                logger.debug("message with '' quote");
                assertEquals(
                        "batchSize=1, so messages should be added immediately",
                        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
                        joinSorted(getMessages()));

                // It should fail
                logger.fatal("message with ' quote");

                assertEquals(
                        "Inserting a message with ' should cause failure in insecure mode, so only one message should be in the DB",
                        "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
                        joinSorted(getMessages()));

                StringBuffer exceptions = new StringBuffer();
                StringBuffer errorCodes = new StringBuffer();
                for (int i = 0; i < errorHandler.size(); i++) {
                    Exception ex = errorHandler.getException(i);
                    exceptions.append(ex.toString());
                    errorCodes.append(
                            ex instanceof SQLException
                                    ? ("SQLException.getErrorCode() = " + ((SQLException) ex).getErrorCode())
                                    : ("SQL Exception expected, got " + ex.getClass()));
                    exceptions.append('\n');
                    errorCodes.append('\n');
                }
                assertEquals(
                        "Logging a message with ' should trigger SQLException 'Syntax error in SQL statement...' when using insecure JDBCAppender mode, actual exceptions are\n" + exceptions,
                        "SQLException.getErrorCode() = 42001\n",
                        errorCodes.toString()
                );
            } finally {
                Thread.currentThread().setName(oldThreadName);
            }
        } finally {
            System.getProperties().remove(SECURE_JDBC_REPLACEMENT);
        }
    }

    public void testJdbcBufferSize1() throws SQLException {
        PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize1.properties");

        Logger logger = Logger.getLogger(JdbcAppenderTest.class);

        String oldThreadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName("main");
            logger.debug("message with ' quote");
            assertEquals(
                    "batchSize=1, so messages should be added immediately",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n",
                    joinSorted(getMessages()));

            logger.fatal("message with \" quote");

            assertEquals(
                    "batchSize=1, so two messages should be in DB after two logging calls",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
                            "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL message with \" quote\n",
                    joinSorted(getMessages()));
        } finally {
            Thread.currentThread().setName(oldThreadName);
        }
    }

    public void testJdbcBufferSize2() throws SQLException {
        PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize2.properties");

        Logger logger = Logger.getLogger(JdbcAppenderTest.class);

        String oldThreadName = Thread.currentThread().getName();
        try {
            Thread.currentThread().setName("main");
            logger.log(XLevel.TRACE, "xtrace message");
            logger.debug("message with ' quote");
            logger.info("message with \" quote");
            logger.warn("?");
            // bufferSize=2, so this messsage won't yet be stored to the db
            logger.error("m4");

            assertEquals(
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
                            "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n" +
                            "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n" +
                            "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
                    joinSorted(getMessages()));

            logger.fatal("m5");

            assertEquals(
                    "Logging m5 message should trigger buffer flush for both m4 and m5",
                    "DEBUG; org.apache.log4j.jdbc.JdbcAppenderTest; message with ' quote;  org.apache.log4j.jdbc.JdbcAppenderTest DEBUG message with ' quote\n" +
                            "ERROR; org.apache.log4j.jdbc.JdbcAppenderTest; m4;  org.apache.log4j.jdbc.JdbcAppenderTest ERROR m4\n" +
                            "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; m5;  org.apache.log4j.jdbc.JdbcAppenderTest FATAL m5\n" +
                            "INFO; org.apache.log4j.jdbc.JdbcAppenderTest; message with \" quote;  org.apache.log4j.jdbc.JdbcAppenderTest INFO message with \" quote\n" +
                            "TRACE; org.apache.log4j.jdbc.JdbcAppenderTest; xtrace message;  org.apache.log4j.jdbc.JdbcAppenderTest TRACE xtrace message\n" +
                            "WARN; org.apache.log4j.jdbc.JdbcAppenderTest; ?;  org.apache.log4j.jdbc.JdbcAppenderTest WARN ?\n",
                    joinSorted(getMessages()));
        } finally {
            Thread.currentThread().setName(oldThreadName);
        }
    }

    /**
     * CVE-2022-23305: the legacy (pre-fix) string concatenation, still
     * reachable through the opt-out system property, lets a logged message
     * inject an extra row. This proves SQL_INJECTION_PAYLOAD is a working
     * exploit for the statement used in the secure-mode tests below.
     */
    public void testSqlInjectionPayloadWorksInInsecureMode() throws SQLException {
        System.setProperty(SECURE_JDBC_REPLACEMENT, "false");
        PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize1.properties");

        Logger.getLogger(JdbcAppenderTest.class).fatal(SQL_INJECTION_PAYLOAD);

        assertEquals(
                "Insecure mode concatenates the message into the SQL, so the payload injects a second row",
                "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; x; y\n" +
                        "I; I; I; I\n",
                joinSorted(getMessages()));
    }

    /**
     * CVE-2022-23305: a logged message (%m) must be stored verbatim and must
     * not be able to alter the SQL statement.
     */
    public void testSqlInjectionThroughMessageIsPrevented() throws SQLException {
        PropertyConfigurator.configure(TEST_INPUT_PREFIX + "jdbc_h2_bufferSize1.properties");
        Appender jdbcAppender = LogManager.getRootLogger().getAppender("A");
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        jdbcAppender.setErrorHandler(errorHandler);

        Logger.getLogger(JdbcAppenderTest.class).fatal(SQL_INJECTION_PAYLOAD);

        assertEquals("No errors expected", 0, errorHandler.size());
        assertEquals(
                "The message must be bound as a value, not concatenated into the SQL",
                "FATAL; org.apache.log4j.jdbc.JdbcAppenderTest; " + SQL_INJECTION_PAYLOAD
                        + ";  org.apache.log4j.jdbc.JdbcAppenderTest FATAL " + SQL_INJECTION_PAYLOAD + "\n",
                joinSorted(getMessages()));
    }

    /**
     * CVE-2022-23305: values from MDC (%X) and NDC (%x) are attacker
     * controllable too (e.g. request headers) and must be bound as values.
     */
    public void testSqlInjectionThroughMdcAndNdcIsPrevented() throws SQLException {
        JDBCAppender appender = createAppender();
        appender.setSql("insert into logs(level,location,message,message2) values('%p','%X{user}','%x', '%m')");
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        appender.setErrorHandler(errorHandler);
        Logger logger = createLogger(appender);

        MDC.put("user", SQL_INJECTION_PAYLOAD);
        NDC.push(SQL_INJECTION_PAYLOAD);
        logger.warn("hello");

        assertEquals("No errors expected", 0, errorHandler.size());
        assertEquals(
                "MDC and NDC values must be bound as values, not concatenated into the SQL",
                "WARN; " + SQL_INJECTION_PAYLOAD + "; " + SQL_INJECTION_PAYLOAD + "; hello\n",
                joinSorted(getMessages()));
    }

    /**
     * CVE-2022-23305: in secure mode a layout other than
     * org.apache.log4j.PatternLayout (here a subclass) must not fall back to
     * concatenating the formatted event into SQL.
     */
    public void testSqlInjectionThroughCustomLayoutIsPrevented() throws SQLException {
        JDBCAppender appender = createAppender();
        appender.setLayout(new PatternLayout(INSERT_SQL) {
        });
        VectorErrorHandler errorHandler = new VectorErrorHandler();
        appender.setErrorHandler(errorHandler);
        Logger logger = createLogger(appender);

        logger.fatal(SQL_INJECTION_PAYLOAD);

        assertEquals("Nothing must be written with an unsupported layout", "", joinSorted(getMessages()));
        assertEquals("One error expected", 1, errorHandler.size());
        assertTrue(
                "IllegalArgumentException expected, got " + errorHandler.getException(0),
                errorHandler.getException(0) instanceof IllegalArgumentException);
        assertEquals(ErrorCode.MISSING_LAYOUT, errorHandler.getErrorCode(0));
    }

    private static JDBCAppender createAppender() {
        JDBCAppender appender = new JDBCAppender();
        appender.setName("exploit");
        appender.setDriver("org.h2.Driver");
        appender.setURL(DB_URL);
        appender.setUser("");
        appender.setPassword("");
        appender.setBufferSize(1);
        return appender;
    }

    private static Logger createLogger(Appender appender) {
        Logger logger = Logger.getLogger(JdbcAppenderTest.class.getName() + ".exploit");
        logger.setAdditivity(false);
        logger.setLevel(Level.ALL);
        logger.addAppender(appender);
        return logger;
    }

    private static String joinSorted(List list) {
        Collections.sort(list);
        StringBuffer sb = new StringBuffer();
        for (Iterator i = list.iterator(); i.hasNext();) {
            sb.append(i.next()).append('\n');
        }
        return sb.toString();
    }

    private List getMessages() throws SQLException {
        List res = new ArrayList();
        PreparedStatement ps = con.prepareStatement("select level,location,message,message2 from logs");
        try {
            ResultSet rs = ps.executeQuery();
            try {
                while (rs.next()) {
                    res.add(rs.getString(1) + "; " + rs.getString(2)
                            + "; " + rs.getString(3) + "; " + rs.getString(4));
                }
            } finally {
                rs.close();
            }
        } finally {
            ps.close();
        }
        return res;
    }
}
