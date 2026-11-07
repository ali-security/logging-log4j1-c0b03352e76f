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
package org.apache.log4j.chainsaw;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.net.HardenedObjectInputStreamTest;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Tests the Chainsaw {@link LoggingReceiver} against CVE-2023-26464.
 */
public class LoggingReceiverTest extends TestCase {

    private static int freePort() throws IOException {
        ServerSocket probe = new ServerSocket(0);
        try {
            return probe.getLocalPort();
        } finally {
            probe.close();
        }
    }

    /**
     * A connection sending deeply nested HashSets is dropped instead of
     * spending exponential time hashing them.
     */
    public void testNestedHashSetPayloadClosesConnection() throws Exception {
        int port = freePort();
        LoggingReceiver receiver = new LoggingReceiver(new MyTableModel(), port);
        receiver.start();

        Socket client = new Socket("localhost", port);
        try {
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            HardenedObjectInputStreamTest.sendObject(oos,
                    HardenedObjectInputStreamTest.createNestedHashSets(100));

            HardenedObjectInputStreamTest.assertConnectionClosedByPeer(client);
        } finally {
            client.close();
        }
    }

    /**
     * Logging events sent over one connection still reach the model.
     */
    public void testLoggingEventsReceived() throws Exception {
        int port = freePort();
        MyTableModel model = new MyTableModel();
        LoggingReceiver receiver = new LoggingReceiver(model, port);
        receiver.start();

        Logger logger = Logger.getLogger(LoggingReceiverTest.class);
        Socket client = new Socket("localhost", port);
        try {
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            for (int i = 0; i < 3; i++) {
                oos.writeObject(new LoggingEvent(Logger.class.getName(), logger, Level.WARN,
                        "message " + i, null));
            }
            oos.flush();

            long deadline = System.currentTimeMillis() + HardenedObjectInputStreamTest.TIMEOUT;
            while (model.getRowCount() < 3 && System.currentTimeMillis() < deadline) {
                Thread.sleep(100);
            }
            assertEquals(3, model.getRowCount());
        } finally {
            client.close();
        }
    }
}
