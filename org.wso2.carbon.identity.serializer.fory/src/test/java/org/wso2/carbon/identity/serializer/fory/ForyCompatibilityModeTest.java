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

import org.testng.annotations.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Runs the serializer in both compatible and non-compatible Fory modes. The mode is fixed at class
 * initialization into a {@code static final} Fory, so one class load observes only one mode; each
 * case loads its own copy of the serializer in an isolating class loader.
 */
public class ForyCompatibilityModeTest {

    private static final String COMPATIBILITY_MODE_PROPERTY = "Fory.EnableCompatibilityMode";
    private static final String SERIALIZER_CLASS =
            "org.wso2.carbon.identity.serializer.fory.ForySessionSerializer";
    private static final String IDENTITY_UTIL_CLASS = "org.wso2.carbon.identity.core.util.IdentityUtil";

    /**
     * Loads the serializer and IdentityUtil locally rather than delegating, so each instance gets a
     * fresh static initializer. Everything else comes from the parent, so objects handed back
     * across the boundary stay the types this test expects.
     */
    private static final class IsolatingClassLoader extends URLClassLoader {

        private static final List<String> ISOLATED_PREFIXES = List.of(SERIALIZER_CLASS, IDENTITY_UTIL_CLASS);

        IsolatingClassLoader(ClassLoader parent) throws IOException {

            super(currentClasspath(), parent);
        }

        private static boolean isIsolated(String name) {

            for (String prefix : ISOLATED_PREFIXES) {
                // Nested classes must stay with their outer class, or the JVM rejects the access.
                if (name.equals(prefix) || name.startsWith(prefix + "$")) {
                    return true;
                }
            }
            return false;
        }

        private static URL[] currentClasspath() throws IOException {

            List<URL> urls = new ArrayList<>();
            for (String entry : System.getProperty("java.class.path").split(File.pathSeparator)) {
                urls.add(new File(entry).toURI().toURL());
            }
            return urls.toArray(new URL[0]);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {

            if (!isIsolated(name)) {
                return super.loadClass(name, resolve);
            }
            synchronized (getClassLoadingLock(name)) {
                Class<?> loaded = findLoadedClass(name);
                if (loaded == null) {
                    loaded = findClass(name);
                }
                if (resolve) {
                    resolveClass(loaded);
                }
                return loaded;
            }
        }
    }

    /**
     * A serializer built in the requested Fory mode.
     */
    private static final class IsolatedSerializer implements AutoCloseable {

        private final URLClassLoader loader;
        private final Class<?> serializerClass;
        private final Object serializer;
        private final Method serialize;
        private final Method deserialize;

        IsolatedSerializer(boolean compatibilityModeEnabled) throws Exception {

            loader = new IsolatingClassLoader(ForyCompatibilityModeTest.class.getClassLoader());
            seedMode(compatibilityModeEnabled);

            // Loading the class runs the static initializer that builds the Fory for this mode.
            serializerClass = loader.loadClass(SERIALIZER_CLASS);
            serializer = serializerClass.getDeclaredConstructor().newInstance();
            serialize = serializerClass.getMethod("serializeSessionObject", Object.class);
            deserialize = serializerClass.getMethod("deSerializeSessionObject", InputStream.class);
        }

        private void seedMode(boolean compatibilityModeEnabled) throws Exception {

            Class<?> identityUtil = loader.loadClass(IDENTITY_UTIL_CLASS);
            Field configuration = identityUtil.getDeclaredField("configuration");
            configuration.setAccessible(true);
            Map<String, Object> seeded = new HashMap<>();
            seeded.put(COMPATIBILITY_MODE_PROPERTY, String.valueOf(compatibilityModeEnabled));
            configuration.set(null, seeded);
        }

        Object roundTrip(Object value) throws Exception {

            try {
                return deserialize.invoke(serializer, serialize.invoke(serializer, value));
            } catch (InvocationTargetException e) {
                if (e.getCause() instanceof Exception) {
                    throw (Exception) e.getCause();
                }
                throw e;
            }
        }

        @Override
        public void close() throws IOException {

            loader.close();
        }
    }

    private static SessionTestModels.TestSessionContext buildSessionContext() {

        SessionTestModels.TestPasswordCredential credential = new SessionTestModels.TestPasswordCredential();
        credential.setIdentifier("primary");
        credential.setSecret("s3cr3t".toCharArray());
        credential.setFailedAttempts(2);

        SessionTestModels.TestAuthenticatedUser user = new SessionTestModels.TestAuthenticatedUser();
        user.setUserName("alice");
        user.setTenantDomain("carbon.super");
        user.getUserAttributes().put("http://wso2.org/claims/emailaddress", "alice@example.com");
        user.setCredential(credential);

        SessionTestModels.TestStepConfig step = new SessionTestModels.TestStepConfig();
        step.setOrder(1);
        step.setAuthenticatedIdP("LOCAL");
        step.setCompleted(true);
        step.setAuthenticatedUser(user);
        step.getAuthenticatorList().add("BasicAuthenticator");

        SessionTestModels.TestSequenceConfig sequenceConfig = new SessionTestModels.TestSequenceConfig();
        sequenceConfig.setApplicationId("my-account");
        sequenceConfig.setAuthenticatedUser(user);
        sequenceConfig.getStepMap().put(1, step);
        sequenceConfig.getRequestedClaims().add("email");

        SessionTestModels.TestSessionContext context = new SessionTestModels.TestSessionContext();
        context.setSessionId("session-1");
        context.setStatus(SessionTestModels.AuthStatus.SUCCESS);
        context.setSequenceConfig(sequenceConfig);
        context.setCreatedAt(new Date(1700000000000L));
        context.setSerializedBlob(new byte[]{1, 2, 3});
        context.setCachedSecret("must-not-be-persisted");
        context.getAuthHistory().add(new SessionTestModels.TestAuthHistory("BasicAuthenticator", "LOCAL", 1L));
        context.getParameters().put("relyingParty", "my-account");
        context.getParameters().put("retryCount", 2);
        context.getParameters().put("forceAuth", Boolean.TRUE);
        context.getParameters().put("absentClaim", null);
        return context;
    }

    @Test
    public void testSessionGraphRoundTripsWithCompatibilityModeEnabled() throws Exception {

        try (IsolatedSerializer isolated = new IsolatedSerializer(true)) {
            assertSessionGraphRoundTrips(isolated);
        }
    }

    @Test
    public void testSessionGraphRoundTripsWithCompatibilityModeDisabled() throws Exception {

        // The non-default mode builds a different Fory, otherwise never exercised.
        try (IsolatedSerializer isolated = new IsolatedSerializer(false)) {
            assertSessionGraphRoundTrips(isolated);
        }
    }

    @Test
    public void testCyclicGraphRoundTripsInBothModes() throws Exception {

        for (boolean compatibilityModeEnabled : new boolean[]{true, false}) {
            try (IsolatedSerializer isolated = new IsolatedSerializer(compatibilityModeEnabled)) {
                SessionTestModels.TestSessionContext context = buildSessionContext();
                context.setPreviousContext(context);

                SessionTestModels.TestSessionContext result =
                        (SessionTestModels.TestSessionContext) isolated.roundTrip(context);

                assertSame(result.getPreviousContext(), result,
                        "Self reference lost with compatibility mode " + compatibilityModeEnabled);
            }
        }
    }

    @Test
    public void testEachModeGetsItsOwnSerializer() throws Exception {

        // Guards the isolation: if the loaders leaked, both cases above would run the same mode.
        try (IsolatedSerializer enabled = new IsolatedSerializer(true);
             IsolatedSerializer disabled = new IsolatedSerializer(false)) {

            assertNotSame(enabled.serializerClass, disabled.serializerClass,
                    "Each isolated loader must define its own serializer class.");
            assertSessionGraphRoundTrips(enabled);
            assertSessionGraphRoundTrips(disabled);
        }
    }

    @Test
    public void testIsolatedLoadingDoesNotDisturbTheSharedSerializer() throws Exception {

        try (IsolatedSerializer isolated = new IsolatedSerializer(false)) {
            assertSessionGraphRoundTrips(isolated);
        }

        ForySessionSerializer shared = new ForySessionSerializer();
        Object deserialized = shared.deSerializeSessionObject(
                shared.serializeSessionObject(buildSessionContext()));
        assertEquals(((SessionTestModels.TestSessionContext) deserialized).getSessionId(), "session-1");
    }

    private void assertSessionGraphRoundTrips(IsolatedSerializer isolated) throws Exception {

        SessionTestModels.TestSessionContext original = buildSessionContext();
        Object deserialized = isolated.roundTrip(original);

        assertNotNull(deserialized);
        // Models come from the parent loader, so the result is the type this test knows.
        assertTrue(deserialized instanceof SessionTestModels.TestSessionContext,
                "Expected a TestSessionContext but got " + deserialized.getClass());
        SessionTestModels.TestSessionContext result = (SessionTestModels.TestSessionContext) deserialized;

        assertEquals(result.getSessionId(), "session-1");
        assertEquals(result.getStatus(), SessionTestModels.AuthStatus.SUCCESS);
        assertEquals(result.getCreatedAt(), new Date(1700000000000L));
        assertEquals(result.getSerializedBlob(), new byte[]{1, 2, 3});
        assertNull(result.getCachedSecret(), "Transient state must not be persisted in either mode.");

        assertEquals(result.getAuthHistory().size(), 1);
        assertEquals(result.getAuthHistory().get(0).getAuthenticatorName(), "BasicAuthenticator");
        assertEquals(result.getParameters().get("relyingParty"), "my-account");
        assertEquals(result.getParameters().get("retryCount"), 2);
        assertEquals(result.getParameters().get("forceAuth"), Boolean.TRUE);
        assertNull(result.getParameters().get("absentClaim"));

        SessionTestModels.TestSequenceConfig sequenceConfig = result.getSequenceConfig();
        assertEquals(sequenceConfig.getApplicationId(), "my-account");
        assertEquals(sequenceConfig.getStepMap().size(), 1);
        assertEquals(sequenceConfig.getRequestedClaims(), original.getSequenceConfig().getRequestedClaims());
        assertEquals(sequenceConfig.getStepMap().get(1).getAuthenticatorList(),
                List.of("BasicAuthenticator"));

        SessionTestModels.TestAuthenticatedUser user = sequenceConfig.getAuthenticatedUser();
        assertEquals(user.getUserName(), "alice");
        assertEquals(user.getUserAttributes().get("http://wso2.org/claims/emailaddress"), "alice@example.com");
        assertTrue(user.getCredential() instanceof SessionTestModels.TestPasswordCredential,
                "Polymorphic field lost its concrete type: " + user.getCredential().getClass());
        assertEquals(new String(((SessionTestModels.TestPasswordCredential) user.getCredential())
                .getSecret()), "s3cr3t");
        assertSame(sequenceConfig.getStepMap().get(1).getAuthenticatedUser(), user,
                "Reference tracking must hold in both modes.");
    }
}
