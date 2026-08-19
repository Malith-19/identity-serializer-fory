/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.serializer.fory;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.SessionSerializerException;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Covers the serializer contract: value round-trips, stream handling and the failure paths that
 * must surface as {@link SessionSerializerException}. Graph scenarios live in
 * {@link ForySessionGraphTest}.
 */
public class ForySessionSerializerTest {

    private ForySessionSerializer serializer;
    private SessionTestModels.TestAuthenticatedUser user;

    @BeforeClass
    public void initSerializer() {

        serializer = new ForySessionSerializer();
    }

    @BeforeMethod
    public void setUp() {

        SessionTestModels.TestPasswordCredential credential = new SessionTestModels.TestPasswordCredential();
        credential.setIdentifier("primary");
        credential.setSecret("s3cr3t".toCharArray());
        credential.setFailedAttempts(1);

        user = new SessionTestModels.TestAuthenticatedUser();
        user.setUserName("alice");
        user.setTenantDomain("carbon.super");
        user.setUserStoreDomain("PRIMARY");
        user.getUserAttributes().put("http://wso2.org/claims/emailaddress", "alice@example.com");
        user.setCredential(credential);
    }

    /**
     * Round-trips a value.
     */
    private Object roundTrip(Object original) throws SessionSerializerException {

        InputStream serialized = serializer.serializeSessionObject(original);
        assertNotNull(serialized, "Serialization must never return a null stream.");
        return serializer.deSerializeSessionObject(serialized);
    }

    @Test
    public void testSerializeSessionObject() throws SessionSerializerException {

        SessionTestModels.TestAuthenticatedUser deserialized =
                (SessionTestModels.TestAuthenticatedUser) roundTrip(user);

        assertEquals(deserialized.getUserName(), user.getUserName());
        assertEquals(deserialized.getTenantDomain(), user.getTenantDomain());
        assertEquals(deserialized.getUserStoreDomain(), user.getUserStoreDomain());
        assertEquals(deserialized.getUserAttributes(), user.getUserAttributes());
        assertEquals(deserialized.getCredential().getIdentifier(), "primary");
    }

    @Test
    public void testNullSessionObjectRoundTrips() throws SessionSerializerException {

        assertNull(roundTrip(null));
    }

    @Test
    public void testDeserializationReadsStreamDeliveredInSmallChunks() throws SessionSerializerException {

        // The framework does not guarantee a single-read stream.
        byte[] bytes = readFully(serializer.serializeSessionObject(user));
        Object deserialized = serializer.deSerializeSessionObject(new ChunkedInputStream(bytes, 1));
        assertEquals(((SessionTestModels.TestAuthenticatedUser) deserialized).getUserName(), "alice");
    }

    @Test
    public void testRepeatedRoundTripsRemainStable() throws SessionSerializerException {

        // Codegen is asynchronous, so early and later round trips take different internal paths.
        for (int i = 0; i < 50; i++) {
            SessionTestModels.TestAuthenticatedUser deserialized =
                    (SessionTestModels.TestAuthenticatedUser) roundTrip(user);
            assertEquals(deserialized.getUserName(), "alice");
            assertEquals(deserialized.getCredential().getIdentifier(), "primary");
        }
    }

    @Test
    public void testConcurrentSerializationIsThreadSafe() throws Exception {

        // The static ThreadSafeFory is shared; session persistence hits it from many threads.
        int threads = 8;
        int iterationsPerThread = 40;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Callable<String>> jobs = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                final String userName = "user-" + t;
                jobs.add(() -> {
                    String last = null;
                    for (int i = 0; i < iterationsPerThread; i++) {
                        SessionTestModels.TestAuthenticatedUser local =
                                new SessionTestModels.TestAuthenticatedUser();
                        local.setUserName(userName);
                        local.setTenantDomain("tenant-" + i);
                        local.getUserAttributes().put("iteration", String.valueOf(i));
                        SessionTestModels.TestAuthenticatedUser result =
                                (SessionTestModels.TestAuthenticatedUser) roundTrip(local);
                        assertEquals(result.getUserName(), userName);
                        assertEquals(result.getUserAttributes().get("iteration"), String.valueOf(i));
                        last = result.getUserName();
                    }
                    return last;
                });
            }
            List<Future<String>> futures = pool.invokeAll(jobs);
            for (int t = 0; t < threads; t++) {
                // get() rethrows any assertion failure or serialization error from the worker.
                assertEquals(futures.get(t).get(60, TimeUnit.SECONDS), "user-" + t);
            }
        } finally {
            pool.shutdownNow();
            assertTrue(pool.awaitTermination(30, TimeUnit.SECONDS), "Worker pool did not shut down.");
        }
    }

    @Test(expectedExceptions = SessionSerializerException.class)
    public void testDeserializeGarbageBytesThrows() throws SessionSerializerException {

        serializer.deSerializeSessionObject(new ByteArrayInputStream(new byte[]{9, 9, 9, 9, 9, 9, 9, 9}));
    }

    @Test(expectedExceptions = SessionSerializerException.class)
    public void testDeserializeEmptyStreamThrows() throws SessionSerializerException {

        serializer.deSerializeSessionObject(new ByteArrayInputStream(new byte[0]));
    }

    @Test(expectedExceptions = SessionSerializerException.class)
    public void testDeserializeTruncatedPayloadThrows() throws SessionSerializerException {

        byte[] bytes = readFully(serializer.serializeSessionObject(user));
        byte[] truncated = new byte[bytes.length / 2];
        System.arraycopy(bytes, 0, truncated, 0, truncated.length);
        serializer.deSerializeSessionObject(new ByteArrayInputStream(truncated));
    }

    @Test(expectedExceptions = SessionSerializerException.class)
    public void testDeserializeFailingStreamThrows() throws SessionSerializerException {

        serializer.deSerializeSessionObject(new InputStream() {
            @Override
            public int read() throws IOException {

                throw new IOException("Simulated read failure.");
            }
        });
    }

    @Test(expectedExceptions = SessionSerializerException.class)
    public void testDeserializeNullStreamThrows() throws SessionSerializerException {

        serializer.deSerializeSessionObject(null);
    }

    @Test(expectedExceptions = SessionSerializerException.class)
    public void testSerializeUnsupportedValueThrows() throws SessionSerializerException {

        // A live Thread cannot be serialized, and must not escape as a raw Fory error.
        SessionTestModels.TestSessionContext context = new SessionTestModels.TestSessionContext();
        context.setSessionId("session-with-unserializable-parameter");
        context.getParameters().put("worker", new Thread("session-worker"));
        serializer.serializeSessionObject(context);
    }

    @Test
    public void testSerializerRecoversAfterSerializationFailure() throws SessionSerializerException {

        // A poisoned session must not leave the shared Fory unusable.
        SessionTestModels.TestSessionContext poisoned = new SessionTestModels.TestSessionContext();
        poisoned.getParameters().put("worker", new Thread("session-worker"));
        try {
            serializer.serializeSessionObject(poisoned);
        } catch (SessionSerializerException expected) {
            // Asserted by testSerializeUnsupportedValueThrows.
        }

        SessionTestModels.TestAuthenticatedUser deserialized =
                (SessionTestModels.TestAuthenticatedUser) roundTrip(user);
        assertEquals(deserialized.getUserName(), "alice");
    }

    @Test
    public void testSerializerRecoversAfterDeserializationFailure() throws SessionSerializerException {

        try {
            serializer.deSerializeSessionObject(new ByteArrayInputStream(new byte[]{1, 2, 3, 4}));
        } catch (SessionSerializerException expected) {
            // Asserted by testDeserializeGarbageBytesThrows.
        }

        SessionTestModels.TestAuthenticatedUser deserialized =
                (SessionTestModels.TestAuthenticatedUser) roundTrip(user);
        assertEquals(deserialized.getUserName(), "alice");
    }

    @Test
    public void testSeparateSerializerInstancesInteroperate() throws SessionSerializerException {

        // The underlying Fory is static, so instances must interoperate.
        ForySessionSerializer writer = new ForySessionSerializer();
        ForySessionSerializer reader = new ForySessionSerializer();
        Object deserialized = reader.deSerializeSessionObject(writer.serializeSessionObject(user));
        assertEquals(((SessionTestModels.TestAuthenticatedUser) deserialized).getUserName(), "alice");
    }

    private static byte[] readFully(InputStream in) throws SessionSerializerException {

        try {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new SessionSerializerException("Could not read the serialized payload.", e);
        }
    }

    /**
     * Hands out the payload in fixed-size chunks.
     */
    private static class ChunkedInputStream extends InputStream {

        private final byte[] data;
        private final int chunkSize;
        private int position;

        ChunkedInputStream(byte[] data, int chunkSize) {

            this.data = data;
            this.chunkSize = chunkSize;
        }

        @Override
        public int read() {

            return position < data.length ? data[position++] & 0xff : -1;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {

            if (position >= data.length) {
                return -1;
            }
            int count = Math.min(Math.min(chunkSize, length), data.length - position);
            System.arraycopy(data, position, buffer, offset, count);
            position += count;
            return count;
        }
    }
}
