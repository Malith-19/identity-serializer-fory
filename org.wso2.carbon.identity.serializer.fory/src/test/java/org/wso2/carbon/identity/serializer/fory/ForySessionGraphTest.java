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
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.SessionSerializerException;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNotSame;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertSame;
import static org.testng.Assert.assertTrue;

/**
 * Exercises the serializer against session-shaped object graphs built from
 * {@link SessionTestModels}: cycles, shared references, polymorphic fields, heterogeneous
 * parameter maps, transient state and large or deep graphs.
 */
public class ForySessionGraphTest {

    private ForySessionSerializer serializer;

    @BeforeClass
    public void initSerializer() {

        serializer = new ForySessionSerializer();
    }

    private Object roundTrip(Object original) throws SessionSerializerException {

        return serializer.deSerializeSessionObject(serializer.serializeSessionObject(original));
    }

    /**
     * Builds a session graph resembling a two-step authentication.
     */
    private SessionTestModels.TestSessionContext buildSessionContext() {

        SessionTestModels.TestPasswordCredential credential = new SessionTestModels.TestPasswordCredential();
        credential.setIdentifier("primary");
        credential.setSecret("s3cr3t".toCharArray());
        credential.setFailedAttempts(2);

        SessionTestModels.TestAuthenticatedUser user = new SessionTestModels.TestAuthenticatedUser();
        user.setUserName("alice");
        user.setTenantDomain("carbon.super");
        user.setUserStoreDomain("PRIMARY");
        user.setFederatedUser(false);
        user.getUserAttributes().put("http://wso2.org/claims/emailaddress", "alice@example.com");
        user.getUserAttributes().put("http://wso2.org/claims/givenname", "Alice");
        user.setCredential(credential);

        SessionTestModels.TestStepConfig firstStep = new SessionTestModels.TestStepConfig();
        firstStep.setOrder(1);
        firstStep.setAuthenticatedIdP("LOCAL");
        firstStep.setCompleted(true);
        firstStep.setAuthenticatedUser(user);
        firstStep.getAuthenticatorList().add("BasicAuthenticator");

        SessionTestModels.TestStepConfig secondStep = new SessionTestModels.TestStepConfig();
        secondStep.setOrder(2);
        secondStep.setAuthenticatedIdP("Google");
        secondStep.setCompleted(false);
        secondStep.getAuthenticatorList().add("TOTPAuthenticator");
        secondStep.getAuthenticatorList().add("EmailOTPAuthenticator");

        SessionTestModels.TestSequenceConfig sequenceConfig = new SessionTestModels.TestSequenceConfig();
        sequenceConfig.setApplicationId("my-account");
        sequenceConfig.setAuthenticatedUser(user);
        sequenceConfig.getStepMap().put(1, firstStep);
        sequenceConfig.getStepMap().put(2, secondStep);
        sequenceConfig.getRequestedClaims().add("email");
        sequenceConfig.getRequestedClaims().add("profile");

        SessionTestModels.TestSessionContext context = new SessionTestModels.TestSessionContext();
        context.setSessionId("c4f1e2d3-0000-4a5b-8c6d-7e8f9a0b1c2d");
        context.setContextIdentifier("ctx-1");
        context.setStatus(SessionTestModels.AuthStatus.INCOMPLETE);
        context.setSequenceConfig(sequenceConfig);
        context.setCreatedAt(new Date(1700000000000L));
        context.setSerializedBlob(new byte[]{1, 2, 3, 4, 5});
        context.setCachedSecret("must-not-be-persisted");
        context.getAuthHistory().add(new SessionTestModels.TestAuthHistory("BasicAuthenticator", "LOCAL", 1L));
        context.getAuthHistory().add(new SessionTestModels.TestAuthHistory("TOTPAuthenticator", "LOCAL", 2L));
        context.getParameters().put("commonAuthCallerPath", "/oauth2/authorize");
        context.getParameters().put("relyingParty", "my-account");
        context.getParameters().put("forceAuth", Boolean.TRUE);
        context.getParameters().put("retryCount", 3);
        context.getParameters().put("expiryTime", 1700000123456L);
        context.getParameters().put("absentClaim", null);
        return context;
    }

    @Test
    public void testFullSessionGraphRoundTrip() throws SessionSerializerException {

        SessionTestModels.TestSessionContext original = buildSessionContext();
        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(original);

        assertNotNull(result);
        assertNotSame(result, original, "Deserialization must produce a new graph.");
        assertEquals(result.getSessionId(), original.getSessionId());
        assertEquals(result.getContextIdentifier(), "ctx-1");
        assertEquals(result.getStatus(), SessionTestModels.AuthStatus.INCOMPLETE);
        assertEquals(result.getCreatedAt(), new Date(1700000000000L));
        assertEquals(result.getSerializedBlob(), new byte[]{1, 2, 3, 4, 5});

        assertEquals(result.getAuthHistory().size(), 2);
        assertEquals(result.getAuthHistory().get(0).getAuthenticatorName(), "BasicAuthenticator");
        assertEquals(result.getAuthHistory().get(1).getTimestamp(), 2L);

        SessionTestModels.TestSequenceConfig sequenceConfig = result.getSequenceConfig();
        assertNotNull(sequenceConfig);
        assertEquals(sequenceConfig.getApplicationId(), "my-account");
        assertEquals(sequenceConfig.getStepMap().size(), 2);
        assertEquals(sequenceConfig.getRequestedClaims(), original.getSequenceConfig().getRequestedClaims());

        SessionTestModels.TestStepConfig firstStep = sequenceConfig.getStepMap().get(1);
        assertNotNull(firstStep, "Step map keyed by boxed Integer must survive the round trip.");
        assertEquals(firstStep.getOrder(), 1);
        assertEquals(firstStep.getAuthenticatedIdP(), "LOCAL");
        assertTrue(firstStep.isCompleted());
        assertEquals(firstStep.getAuthenticatorList(), Arrays.asList("BasicAuthenticator"));

        SessionTestModels.TestStepConfig secondStep = sequenceConfig.getStepMap().get(2);
        assertTrue(!secondStep.isCompleted());
        assertEquals(secondStep.getAuthenticatorList(),
                Arrays.asList("TOTPAuthenticator", "EmailOTPAuthenticator"));
        assertNull(secondStep.getAuthenticatedUser());

        SessionTestModels.TestAuthenticatedUser user = sequenceConfig.getAuthenticatedUser();
        assertEquals(user.getUserName(), "alice");
        assertEquals(user.getTenantDomain(), "carbon.super");
        assertEquals(user.getUserStoreDomain(), "PRIMARY");
        assertTrue(!user.isFederatedUser());
        assertEquals(user.getUserAttributes().get("http://wso2.org/claims/emailaddress"), "alice@example.com");
        assertEquals(user.getUserAttributes().size(), 2);
    }

    @Test
    public void testHeterogeneousParameterMapRoundTrip() throws SessionSerializerException {

        // Value types are only known at runtime, so each takes a different path through Fory.
        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(buildSessionContext());
        Map<String, Object> parameters = result.getParameters();

        assertEquals(parameters.size(), 6);
        assertEquals(parameters.get("commonAuthCallerPath"), "/oauth2/authorize");
        assertEquals(parameters.get("forceAuth"), Boolean.TRUE);
        assertEquals(parameters.get("retryCount"), 3);
        assertEquals(parameters.get("expiryTime"), 1700000123456L);
        assertNull(parameters.get("absentClaim"));
        assertTrue(parameters.containsKey("absentClaim"), "A null-valued parameter key must be kept.");
    }

    @Test
    public void testNestedCollectionsInParameterMap() throws SessionSerializerException {

        SessionTestModels.TestSessionContext context = new SessionTestModels.TestSessionContext();
        context.setSessionId("nested");
        Map<String, Integer> counts = new HashMap<>();
        counts.put("attempts", 2);
        Map<String, Object> nested = new HashMap<>();
        nested.put("scopes", Arrays.asList("openid", "profile", "email"));
        nested.put("counts", counts);
        context.getParameters().put("oauth", nested);
        context.getParameters().put("acrValues", Arrays.asList("acr1", "acr2"));

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(context);

        Map<?, ?> resultNested = (Map<?, ?>) result.getParameters().get("oauth");
        assertEquals(resultNested.get("scopes"), Arrays.asList("openid", "profile", "email"));
        assertEquals(((Map<?, ?>) resultNested.get("counts")).get("attempts"), 2);
        assertEquals(result.getParameters().get("acrValues"), Arrays.asList("acr1", "acr2"));
    }

    @Test
    public void testAlternativeCollectionImplementationsRoundTrip() throws SessionSerializerException {

        // The concrete type must be kept so ordering guarantees survive.
        SessionTestModels.TestSessionContext context = new SessionTestModels.TestSessionContext();
        Map<String, Object> ordered = new LinkedHashMap<>();
        ordered.put("z", 1);
        ordered.put("a", 2);
        ordered.put("m", 3);
        context.getParameters().put("ordered", ordered);
        context.getParameters().put("sorted", new TreeMap<>(ordered));
        context.getParameters().put("sortedSet", new TreeSet<>(Arrays.asList("c", "a", "b")));
        context.getParameters().put("linked", new LinkedList<>(Arrays.asList("first", "second")));

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(context);

        Object resultOrdered = result.getParameters().get("ordered");
        assertTrue(resultOrdered instanceof LinkedHashMap,
                "Expected LinkedHashMap but got " + resultOrdered.getClass());
        assertEquals(new java.util.ArrayList<>(((Map<?, ?>) resultOrdered).keySet()),
                Arrays.asList("z", "a", "m"), "LinkedHashMap ordering must be preserved.");
        assertTrue(result.getParameters().get("sorted") instanceof TreeMap);
        assertEquals(((TreeMap<?, ?>) result.getParameters().get("sorted")).firstKey(), "a");
        assertEquals(result.getParameters().get("sortedSet"), new TreeSet<>(Arrays.asList("a", "b", "c")));
        assertEquals(result.getParameters().get("linked"), new LinkedList<>(Arrays.asList("first", "second")));
    }

    @Test
    public void testSharedReferenceIdentityPreserved() throws SessionSerializerException {

        // Without ref tracking the session would grow on every persist/reload cycle.
        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(buildSessionContext());

        SessionTestModels.TestAuthenticatedUser fromSequence = result.getSequenceConfig().getAuthenticatedUser();
        SessionTestModels.TestAuthenticatedUser fromStep =
                result.getSequenceConfig().getStepMap().get(1).getAuthenticatedUser();
        assertSame(fromStep, fromSequence, "A shared reference must stay shared after deserialization.");
    }

    @Test
    public void testSelfReferencingContextRoundTrip() throws SessionSerializerException {

        SessionTestModels.TestSessionContext context = buildSessionContext();
        context.setPreviousContext(context);

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(context);

        assertSame(result.getPreviousContext(), result, "A self reference must resolve back to the root.");
    }

    @Test
    public void testMutualBackReferenceRoundTrip() throws SessionSerializerException {

        SessionTestModels.TestSessionContext current = buildSessionContext();
        SessionTestModels.TestSessionContext previous = buildSessionContext();
        previous.setSessionId("previous-session");
        current.setPreviousContext(previous);
        previous.setPreviousContext(current);

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(current);

        assertEquals(result.getPreviousContext().getSessionId(), "previous-session");
        assertSame(result.getPreviousContext().getPreviousContext(), result,
                "A two-node cycle must be restored, not expanded.");
    }

    @Test
    public void testTransientStateIsNotPersisted() throws SessionSerializerException {

        // Fory skips transient fields, matching Java serialization.
        SessionTestModels.TestSessionContext original = buildSessionContext();
        assertEquals(original.getCachedSecret(), "must-not-be-persisted");

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(original);

        assertNull(result.getCachedSecret(), "Transient session state must not survive serialization.");
        assertEquals(result.getSessionId(), original.getSessionId(),
                "Non-transient fields on the same object must still be restored.");
    }

    @Test
    public void testPolymorphicCredentialFieldKeepsConcreteType() throws SessionSerializerException {

        SessionTestModels.TestSessionContext context = buildSessionContext();
        SessionTestModels.TestFederatedCredential federated = new SessionTestModels.TestFederatedCredential();
        federated.setIdentifier("google-sub-123");
        federated.setIdpName("Google");
        federated.getAttributes().put("sub", "123");
        context.getSequenceConfig().getAuthenticatedUser().setCredential(federated);

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(context);

        SessionTestModels.TestCredential credential =
                result.getSequenceConfig().getAuthenticatedUser().getCredential();
        assertTrue(credential instanceof SessionTestModels.TestFederatedCredential,
                "A field declared as the supertype must deserialize to the concrete subtype, got "
                        + credential.getClass());
        assertEquals(credential.getType(), "FEDERATED");
        assertEquals(credential.getIdentifier(), "google-sub-123");
        assertEquals(((SessionTestModels.TestFederatedCredential) credential).getIdpName(), "Google");
        assertEquals(((SessionTestModels.TestFederatedCredential) credential).getAttributes().get("sub"), "123");
    }

    @Test
    public void testSubclassFieldsRoundTripThroughSupertypeField() throws SessionSerializerException {

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(buildSessionContext());

        SessionTestModels.TestCredential credential =
                result.getSequenceConfig().getAuthenticatedUser().getCredential();
        assertTrue(credential instanceof SessionTestModels.TestPasswordCredential);
        SessionTestModels.TestPasswordCredential password =
                (SessionTestModels.TestPasswordCredential) credential;
        assertEquals(new String(password.getSecret()), "s3cr3t");
        assertEquals(password.getFailedAttempts(), 2);
        assertEquals(password.getIdentifier(), "primary", "Inherited fields must be restored too.");
    }

    @Test
    public void testEmptySessionContextRoundTrip() throws SessionSerializerException {

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(new SessionTestModels.TestSessionContext());

        assertNotNull(result);
        assertNull(result.getSessionId());
        assertNull(result.getSequenceConfig());
        assertNull(result.getStatus());
        assertNull(result.getCreatedAt());
        assertTrue(result.getParameters().isEmpty());
        assertTrue(result.getAuthHistory().isEmpty());
    }

    @Test
    public void testSessionContextWithNulledCollectionsRoundTrip() throws SessionSerializerException {

        SessionTestModels.TestSessionContext context = new SessionTestModels.TestSessionContext();
        context.setParameters(null);
        context.setAuthHistory(null);
        context.setSerializedBlob(null);

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(context);

        assertNull(result.getParameters());
        assertNull(result.getAuthHistory());
        assertNull(result.getSerializedBlob());
    }

    @Test
    public void testAllEnumConstantsRoundTrip() throws SessionSerializerException {

        for (SessionTestModels.AuthStatus status : SessionTestModels.AuthStatus.values()) {
            SessionTestModels.TestSessionContext context = new SessionTestModels.TestSessionContext();
            context.setStatus(status);
            SessionTestModels.TestSessionContext result =
                    (SessionTestModels.TestSessionContext) roundTrip(context);
            assertEquals(result.getStatus(), status);
            assertSame(result.getStatus(), status, "Enum constants must deserialize to the same instance.");
        }
    }

    @Test
    public void testWideSessionGraphRoundTrip() throws SessionSerializerException {

        SessionTestModels.TestSessionContext context = buildSessionContext();
        for (int i = 3; i <= 500; i++) {
            SessionTestModels.TestStepConfig step = new SessionTestModels.TestStepConfig();
            step.setOrder(i);
            step.setAuthenticatedIdP("idp-" + i);
            step.getAuthenticatorList().add("authenticator-" + i);
            context.getSequenceConfig().getStepMap().put(i, step);
        }
        for (int i = 0; i < 2000; i++) {
            context.getAuthHistory().add(new SessionTestModels.TestAuthHistory("auth-" + i, "idp", i));
        }
        for (int i = 0; i < 1000; i++) {
            context.getParameters().put("param-" + i, "value-" + i);
        }

        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(context);

        assertEquals(result.getSequenceConfig().getStepMap().size(), 500);
        assertEquals(result.getSequenceConfig().getStepMap().get(500).getAuthenticatedIdP(), "idp-500");
        assertEquals(result.getAuthHistory().size(), 2002);
        assertEquals(result.getAuthHistory().get(2001).getAuthenticatorName(), "auth-1999");
        assertEquals(result.getParameters().get("param-999"), "value-999");
    }

    /**
     * Builds a {@code depth} node chain linked through {@code previousContext}.
     */
    private SessionTestModels.TestSessionContext buildContextChain(int depth) {

        SessionTestModels.TestSessionContext head = new SessionTestModels.TestSessionContext();
        head.setSessionId("ctx-0");
        SessionTestModels.TestSessionContext cursor = head;
        for (int i = 1; i < depth; i++) {
            SessionTestModels.TestSessionContext next = new SessionTestModels.TestSessionContext();
            next.setSessionId("ctx-" + i);
            cursor.setPreviousContext(next);
            cursor = next;
        }
        return head;
    }

    @Test
    public void testNestedContextChainRoundTrips() throws SessionSerializerException {

        // Kept well inside Fory's default max read depth of 50. The exact number of depth levels a
        // node consumes is a Fory internal and varies between environments, so this stays clear of
        // the boundary rather than pinning it.
        int depth = 25;
        SessionTestModels.TestSessionContext result =
                (SessionTestModels.TestSessionContext) roundTrip(buildContextChain(depth));

        int walked = 0;
        SessionTestModels.TestSessionContext node = result;
        while (node != null) {
            assertEquals(node.getSessionId(), "ctx-" + walked);
            node = node.getPreviousContext();
            walked++;
        }
        assertEquals(walked, depth, "The whole context chain must be restored.");
    }

    @Test(expectedExceptions = SessionSerializerException.class)
    public void testExcessivelyDeepContextChainIsRejected() throws SessionSerializerException {

        // Serialization succeeds; only the read is refused, so an over-deep session fails when it is
        // loaded rather than when it is written. Starts failing if the serializer ever calls
        // ForyBuilder#withMaxDepth.
        roundTrip(buildContextChain(200));
    }

    @Test
    public void testRoundTripIsRepeatableForTheSameGraph() throws SessionSerializerException {

        SessionTestModels.TestSessionContext original = buildSessionContext();
        for (int i = 0; i < 20; i++) {
            SessionTestModels.TestSessionContext result =
                    (SessionTestModels.TestSessionContext) roundTrip(original);
            assertEquals(result.getSessionId(), original.getSessionId());
            assertEquals(result.getSequenceConfig().getStepMap().size(), 2);
            assertSame(result.getSequenceConfig().getStepMap().get(1).getAuthenticatedUser(),
                    result.getSequenceConfig().getAuthenticatedUser());
        }
    }

    @Test
    public void testReserializingADeserializedGraphIsStable() throws SessionSerializerException {

        // A deserialized graph must survive being fed straight back in.
        SessionTestModels.TestSessionContext first =
                (SessionTestModels.TestSessionContext) roundTrip(buildSessionContext());
        SessionTestModels.TestSessionContext second =
                (SessionTestModels.TestSessionContext) roundTrip(first);
        SessionTestModels.TestSessionContext third =
                (SessionTestModels.TestSessionContext) roundTrip(second);

        assertEquals(third.getSessionId(), first.getSessionId());
        assertEquals(third.getSequenceConfig().getAuthenticatedUser().getUserName(), "alice");
        assertEquals(third.getAuthHistory().size(), 2);
        assertNull(third.getCachedSecret());
        assertSame(third.getSequenceConfig().getStepMap().get(1).getAuthenticatedUser(),
                third.getSequenceConfig().getAuthenticatedUser());
    }
}
