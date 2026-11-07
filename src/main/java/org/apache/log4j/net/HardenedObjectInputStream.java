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

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.apache.log4j.helpers.LogLog;

/**
 * HardenedObjectInputStream restricts the set of classes that can be
 * deserialized to a set of explicitly whitelisted classes. This prevents
 * certain type of attacks from being successful.
 * 
 * <p>
 * It is assumed that classes in the "java.lang" and "java.util" packages are
 * always authorized.
 * </p>
 * 
 * @author Ceki G&uuml;lc&uuml;
 * @since 1.2.18
 * 
 *        === Copied from the logback project with permission ==
 */
public class HardenedObjectInputStream extends ObjectInputStream {

	static final String ARRAY_CLASS_PREFIX = "[L";
	final List whitelistedClassNames;
	final static String[] JAVA_PACKAGES = new String[] { "java.lang", "java.util", ARRAY_CLASS_PREFIX + "java.lang" };

	/**
	 * Maximum number of Map/Collection instances allowed during deserialization
	 * of a single object graph. This mitigates CVE-2023-26464 where deeply
	 * nested hash-based collections cause exponential hashCode() computation.
	 *
	 * With N collection objects, the worst-case hashCode cost is O(2^(N/2)).
	 * A limit of 32 bounds this to O(2^16) = ~65K operations.
	 * A normal LoggingEvent has 1-2 collections (MDC Hashtable, properties).
	 */
	static final int MAX_COLLECTION_COUNT = 32;

	/**
	 * Maximum nesting depth of a deserialized object graph, enforced through
	 * the JRE's serialization filter (JEP 290) when available. Deeply nested
	 * maps and tables allocate their bucket arrays, sized from the stream,
	 * before their nested entries are read, so the collection count alone
	 * cannot stop CVE-2023-26464 memory exhaustion.
	 */
	static final int DEPTH_LIMIT = 16;

	/**
	 * Maximum array length (including the bucket arrays of hash-based
	 * collections) accepted through the JRE's serialization filter.
	 */
	static final int ARRAY_LIMIT = 10000;

	private int collectionCount = 0;

	public HardenedObjectInputStream(InputStream in, String[] whilelist) throws IOException {
		super(in);
		enableResolveObject(true);
		initObjectFilter();

		this.whitelistedClassNames = new ArrayList();
		if (whilelist != null) {
			for (int i = 0; i < whilelist.length; i++) {
				this.whitelistedClassNames.add(whilelist[i]);
			}
		}
	}

	public HardenedObjectInputStream(InputStream in, List whitelist) throws IOException {
		super(in);
		enableResolveObject(true);
		initObjectFilter();

		this.whitelistedClassNames = new ArrayList();
		this.whitelistedClassNames.addAll(whitelist);
	}

	/**
	 * Installs a serialization filter limiting the nesting depth and array
	 * sizes of the deserialized object graph, unless a process-wide filter is
	 * already configured. The filter API (java.io.ObjectInputFilter on Java 9+,
	 * sun.misc.ObjectInputFilter on JREs with the JEP 290 backport) is invoked
	 * by reflection; on JREs lacking it the collection count limit enforced in
	 * {@link #resolveObject(Object)} remains in place.
	 */
	private void initObjectFilter() {
		String pattern = "maxarray=" + ARRAY_LIMIT + ";maxdepth=" + DEPTH_LIMIT + ";";
		try {
			Class filterClass = Class.forName("java.io.ObjectInputFilter");
			Class configClass = Class.forName("java.io.ObjectInputFilter$Config");
			Method getFilter = ObjectInputStream.class.getMethod("getObjectInputFilter", new Class[0]);
			if (getFilter.invoke(this, new Object[0]) == null) {
				Object filter = configClass.getMethod("createFilter", new Class[] { String.class })
						.invoke(null, new Object[] { pattern });
				ObjectInputStream.class.getMethod("setObjectInputFilter", new Class[] { filterClass })
						.invoke(this, new Object[] { filter });
			}
			return;
		} catch (ClassNotFoundException e) {
			// not Java 9+, try the JEP 290 backport below
		} catch (Exception e) {
			LogLog.debug("Could not install serialization filter.", e);
			return;
		}
		try {
			Class filterClass = Class.forName("sun.misc.ObjectInputFilter");
			Class configClass = Class.forName("sun.misc.ObjectInputFilter$Config");
			Method getFilter = configClass.getMethod("getObjectInputFilter", new Class[] { ObjectInputStream.class });
			if (getFilter.invoke(null, new Object[] { this }) == null) {
				Object filter = configClass.getMethod("createFilter", new Class[] { String.class })
						.invoke(null, new Object[] { pattern });
				configClass.getMethod("setObjectInputFilter", new Class[] { ObjectInputStream.class, filterClass })
						.invoke(null, new Object[] { this, filter });
			}
		} catch (ClassNotFoundException e) {
			LogLog.debug("Serialization filter not supported by this JRE.");
		} catch (Exception e) {
			LogLog.debug("Could not install serialization filter.", e);
		}
	}

	protected Class resolveClass(ObjectStreamClass anObjectStreamClass) throws IOException, ClassNotFoundException {

		String incomingClassName = anObjectStreamClass.getName();

		if (!isWhitelisted(incomingClassName)) {
			throw new InvalidClassException("Unauthorized deserialization attempt", incomingClassName);
		}

		return super.resolveClass(anObjectStreamClass);
	}

	private boolean isWhitelisted(String incomingClassName) {
		for (int i = 0; i < JAVA_PACKAGES.length; i++) {
			if (incomingClassName.startsWith(JAVA_PACKAGES[i]))
				return true;
		}
		for (int i = 0; i < whitelistedClassNames.size(); i++) {
			String whiteListed = (String) whitelistedClassNames.get(i);
			if (incomingClassName.equals(whiteListed))
				return true;
		}
		return false;
	}

	/**
	 * Reads an object from the stream, resetting the collection counter
	 * so that each top-level readObject call gets its own budget.
	 * Callers should use this instead of {@link #readObject()} directly
	 * when reading multiple objects from the same stream.
	 */
	public Object readAdaptedObject() throws IOException, ClassNotFoundException {
		collectionCount = 0;
		return readObject();
	}

	/**
	 * Counts Map and Collection instances during deserialization to prevent
	 * CVE-2023-26464: deeply nested hash-based collections cause exponential
	 * hashCode() computation during deserialization.
	 */
	protected Object resolveObject(Object obj) throws IOException {
		if (obj instanceof Map || obj instanceof Collection) {
			collectionCount++;
			if (collectionCount > MAX_COLLECTION_COUNT) {
				throw new InvalidObjectException(
					"Exceeded maximum number of collection objects during deserialization: "
					+ MAX_COLLECTION_COUNT
					+ ". Possible CVE-2023-26464 attack via nested collections.");
			}
		}
		return super.resolveObject(obj);
	}

	protected void addToWhitelist(List additionalAuthorizedClasses) {
		whitelistedClassNames.addAll(additionalAuthorizedClasses);
	}
}