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
package org.apache.log4j.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Set;

import junit.framework.TestCase;

import org.apache.log4j.Level;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.apache.log4j.spi.LoggingEvent;

/**
 * Tests for {@link HardenedObjectInputStream} collection count limiting
 * that mitigates CVE-2023-26464.
 *
 * CVE-2023-26464: Deeply nested hash-based collection structures cause
 * exponential hashCode() computation during deserialization, leading
 * to Denial of Service. The fix limits the total number of Map/Collection
 * instances that can be deserialized in a single object graph.
 */
public class HardenedObjectInputStreamTest extends TestCase {

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        oos.writeObject(obj);
        oos.close();
        return bos.toByteArray();
    }

    /**
     * CVE-2023-26464: The exact attack payload from the logback advisory.
     * Deeply nested HashSet structures that cause exponential hashCode()
     * computation. The collection count limit must reject this before
     * the computation becomes dangerous.
     */
    public void testDeeplyNestedHashSetRejected() throws Exception {
        // Build the CVE-2023-26464 attack payload: deeply nested HashSets
        // that form a DAG causing O(2^N) hashCode() computation
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < 100; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        byte[] serialized = serialize(root);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        try {
            hois.readObject();
            fail("Deeply nested HashSet should be rejected due to collection count limit");
        } catch (InvalidObjectException e) {
            // Our resolveObject-based collection count limit caught it (pre-JDK 9)
            assertTrue("Should mention collection limit",
                    e.getMessage().contains("collection"));
        } catch (java.io.InvalidClassException e) {
            // On JDK 9+, the built-in ObjectInputFilter may reject it first
            // with "filter status: REJECTED". Either way, the attack is blocked.
        } finally {
            hois.close();
        }
    }

    /**
     * A moderate number of nested collections (within the limit) should
     * still be allowed. This tests that normal LoggingEvent-like payloads
     * with a few Hashtables work fine.
     */
    public void testModerateCollectionsAllowed() throws Exception {
        // Simulate a LoggingEvent with MDC (Hashtable) containing a few entries
        Hashtable mdc = new Hashtable();
        mdc.put("user", "alice");
        mdc.put("session", "abc123");
        mdc.put("requestId", "req-456");
        byte[] serialized = serialize(mdc);

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        Object result = hois.readObject();
        assertTrue(result instanceof Hashtable);
        assertEquals("alice", ((Hashtable) result).get("user"));
        hois.close();
    }

    /**
     * Simple non-collection objects should work unaffected.
     */
    public void testStringAllowed() throws Exception {
        byte[] serialized = serialize("hello world");

        ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
        String[] whitelist = new String[0];
        HardenedObjectInputStream hois = new HardenedObjectInputStream(bis, whitelist);

        assertEquals("hello world", hois.readObject());
        hois.close();
    }

    /**
     * The collection count limit applies to shallow graphs as well: more
     * than MAX_COLLECTION_COUNT collections in one object are rejected.
     */
    public void testCollectionCountLimitEnforcedOnShallowGraph() throws Exception {
        List list = new ArrayList();
        for (int i = 0; i < HardenedObjectInputStream.MAX_COLLECTION_COUNT; i++) {
            list.add(new HashSet());
        }
        // MAX_COLLECTION_COUNT sets plus the enclosing list
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(list)), new String[0]);
        try {
            hois.readAdaptedObject();
            fail("More than " + HardenedObjectInputStream.MAX_COLLECTION_COUNT
                    + " collections should be rejected");
        } catch (InvalidObjectException e) {
            assertTrue("Should mention collection limit",
                    e.getMessage().indexOf("collection") >= 0);
        } finally {
            hois.close();
        }
    }

    /**
     * Up to MAX_COLLECTION_COUNT collections in one object are accepted.
     */
    public void testCollectionCountUpToLimitAllowed() throws Exception {
        List list = new ArrayList();
        for (int i = 0; i < HardenedObjectInputStream.MAX_COLLECTION_COUNT - 1; i++) {
            list.add(new HashSet());
        }
        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(serialize(list)), new String[0]);
        try {
            List result = (List) hois.readAdaptedObject();
            assertEquals(HardenedObjectInputStream.MAX_COLLECTION_COUNT - 1, result.size());
        } finally {
            hois.close();
        }
    }

    /**
     * readAdaptedObject, used by SocketNode and Chainsaw for every event of a
     * connection, gives each object its own collection budget.
     */
    public void testReadAdaptedObjectResetsCollectionBudget() throws Exception {
        int count = 2 * HardenedObjectInputStream.MAX_COLLECTION_COUNT;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        for (int i = 0; i < count; i++) {
            Hashtable mdc = new Hashtable();
            mdc.put("requestId", "req-" + i);
            oos.writeObject(mdc);
        }
        oos.close();

        HardenedObjectInputStream hois = new HardenedObjectInputStream(
                new ByteArrayInputStream(bos.toByteArray()), new String[0]);
        try {
            for (int i = 0; i < count; i++) {
                Hashtable mdc = (Hashtable) hois.readAdaptedObject();
                assertEquals("req-" + i, mdc.get("requestId"));
            }
        } finally {
            hois.close();
        }
    }

    /**
     * LoggingEvents carrying an MDC and a throwable, as sent by
     * SocketAppender, are still read one after another from a single stream.
     */
    public void testLoggingEventsReadFromOneStream() throws Exception {
        Logger logger = Logger.getLogger(HardenedObjectInputStreamTest.class);
        int count = 2 * HardenedObjectInputStream.MAX_COLLECTION_COUNT;
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos);
        MDC.put("user", "alice");
        try {
            for (int i = 0; i < count; i++) {
                oos.writeObject(new LoggingEvent(Logger.class.getName(), logger, Level.WARN,
                        "message " + i, new Exception("failure " + i)));
            }
        } finally {
            MDC.remove("user");
        }
        oos.close();

        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(bos.toByteArray()));
        try {
            for (int i = 0; i < count; i++) {
                LoggingEvent event = (LoggingEvent) hleis.readAdaptedObject();
                assertEquals("message " + i, event.getRenderedMessage());
                assertEquals(Level.WARN, event.getLevel());
                assertEquals("alice", event.getMDC("user"));
                assertEquals("java.lang.Exception: failure " + i, event.getThrowableStrRep()[0]);
            }
        } finally {
            hleis.close();
        }
    }

    /**
     * CVE-2023-26464 memory exhaustion: deeply nested HashMaps whose declared
     * size makes every level allocate a large bucket array before the nested
     * map is read must be rejected before the heap is exhausted.
     */
    public void testNestedHashMapsWithInflatedSizeRejected() throws Exception {
        assertNestedMapsRejected(HashMap.class);
    }

    /**
     * Same as {@link #testNestedHashMapsWithInflatedSizeRejected()} for
     * Hashtable, the type of the MDC carried by LoggingEvent.
     */
    public void testNestedHashtablesWithInflatedSizeRejected() throws Exception {
        assertNestedMapsRejected(Hashtable.class);
    }

    /**
     * CVE-2023-26464 against a SocketServer/SimpleSocketServer: SocketNode
     * must drop a connection sending deeply nested HashSets instead of
     * spending exponential time hashing them.
     */
    public void testSocketNodeDropsNestedHashSetPayload() throws Exception {
        ServerSocket serverSocket = new ServerSocket(0);
        Socket client = null;
        try {
            client = new Socket("localhost", serverSocket.getLocalPort());
            Socket accepted = serverSocket.accept();
            ObjectOutputStream oos = new ObjectOutputStream(client.getOutputStream());
            // the SocketNode constructor reads the stream header
            oos.flush();
            Thread node = new Thread(new SocketNode(accepted, LogManager.getLoggerRepository()));
            node.setDaemon(true);
            node.start();

            sendObject(oos, createNestedHashSets(100));

            assertConnectionClosedByPeer(client);
            node.join(TIMEOUT);
            assertFalse("SocketNode should stop after rejecting the payload", node.isAlive());
        } finally {
            if (client != null) {
                client.close();
            }
            serverSocket.close();
        }
    }

    public static final int TIMEOUT = 30000;

    /**
     * Builds the nested HashSet graph of the CVE-2023-26464 attack: both sets
     * of a level contain both sets of the next level, so computing the
     * hashCode of the root costs O(2^levels).
     */
    public static Set createNestedHashSets(int levels) {
        Set root = new HashSet();
        Set s1 = root;
        Set s2 = new HashSet();
        for (int i = 0; i < levels; i++) {
            Set t1 = new HashSet();
            Set t2 = new HashSet();
            t1.add("foo");
            s1.add(t1);
            s1.add(t2);
            s2.add(t1);
            s2.add(t2);
            s1 = t1;
            s2 = t2;
        }
        return root;
    }

    /**
     * Sends an object to a receiver, which may reject it and drop the
     * connection before the whole object has been written.
     */
    public static void sendObject(ObjectOutputStream oos, Object obj) throws IOException {
        try {
            oos.writeObject(obj);
            oos.flush();
        } catch (SocketException e) {
            // connection already dropped by the receiver
        }
    }

    /**
     * Waits for the receiving end of a connection to close it, which happens
     * once it has given up deserializing the payload sent over it.
     */
    public static void assertConnectionClosedByPeer(Socket client) throws IOException {
        client.setSoTimeout(TIMEOUT);
        try {
            assertEquals("receiver should close the connection", -1, client.getInputStream().read());
        } catch (SocketTimeoutException e) {
            fail("receiver is still deserializing the nested collection payload");
        } catch (SocketException e) {
            // connection reset: the receiver closed the socket with unread data
        }
    }

    private void assertNestedMapsRejected(Class mapClass) throws Exception {
        byte[] payload = serializeNestedMapsWithInflatedSize(mapClass, 300, 1 << 21);
        HardenedLoggingEventInputStream hleis = new HardenedLoggingEventInputStream(
                new ByteArrayInputStream(payload));
        try {
            hleis.readAdaptedObject();
            fail("Nested " + mapClass.getName() + " payload should be rejected");
        } catch (InvalidClassException e) {
            assertTrue("Should be rejected by the serialization filter: " + e.getMessage(),
                    e.getMessage().indexOf("REJECTED") >= 0);
        } catch (OutOfMemoryError e) {
            fail("Nested " + mapClass.getName() + " payload exhausted the heap: " + e);
        } finally {
            hleis.close();
        }
    }

    /**
     * Serializes {@code levels} maps nested in one another and rewrites the
     * capacity and size every one of them declares in the stream to
     * {@code declaredSize}. When read back, each level allocates a bucket
     * array for {@code declaredSize} entries before reading its nested map,
     * so the allocations of all levels are held at the same time.
     */
    private byte[] serializeNestedMapsWithInflatedSize(Class mapClass, int levels, int declaredSize)
            throws Exception {
        Map map = (Map) mapClass.newInstance();
        map.put("key", "value");
        for (int i = 1; i < levels; i++) {
            Map outer = (Map) mapClass.newInstance();
            outer.put("key", map);
            map = outer;
        }
        byte[] data = serialize(map);

        // HashMap and Hashtable write their fields loadFactor (0.75f) and
        // threshold, followed by an 8 byte data block holding capacity and size.
        int rewritten = 0;
        for (int i = 0; i + 18 <= data.length; i++) {
            if (data[i] == 0x3F && data[i + 1] == 0x40 && data[i + 2] == 0 && data[i + 3] == 0
                    && data[i + 8] == 0x77 && data[i + 9] == 0x08) {
                writeInt(data, i + 10, declaredSize);
                writeInt(data, i + 14, declaredSize);
                rewritten++;
            }
        }
        assertEquals("every nested map should declare the inflated size", levels, rewritten);
        return data;
    }

    private static void writeInt(byte[] data, int offset, int value) {
        data[offset] = (byte) (value >>> 24);
        data[offset + 1] = (byte) (value >>> 16);
        data[offset + 2] = (byte) (value >>> 8);
        data[offset + 3] = (byte) value;
    }
}
