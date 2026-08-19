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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Stand-in models mirroring the shape of a persisted identity session, without depending on the
 * real framework classes.
 */
public final class SessionTestModels {

    private SessionTestModels() {

    }

    /**
     * Authentication flow status.
     */
    public enum AuthStatus {
        SUCCESS, FAILED, INCOMPLETE
    }

    /**
     * Base of a polymorphic hierarchy.
     */
    public abstract static class TestCredential implements Serializable {

        private String identifier;

        public String getIdentifier() {

            return identifier;
        }

        public void setIdentifier(String identifier) {

            this.identifier = identifier;
        }

        public abstract String getType();
    }

    /**
     * Local credential variant.
     */
    public static class TestPasswordCredential extends TestCredential {

        private char[] secret;
        private int failedAttempts;

        public char[] getSecret() {

            return secret;
        }

        public void setSecret(char[] secret) {

            this.secret = secret;
        }

        public int getFailedAttempts() {

            return failedAttempts;
        }

        public void setFailedAttempts(int failedAttempts) {

            this.failedAttempts = failedAttempts;
        }

        @Override
        public String getType() {

            return "PASSWORD";
        }
    }

    /**
     * Federated credential variant.
     */
    public static class TestFederatedCredential extends TestCredential {

        private String idpName;
        private Map<String, String> attributes = new HashMap<>();

        public String getIdpName() {

            return idpName;
        }

        public void setIdpName(String idpName) {

            this.idpName = idpName;
        }

        public Map<String, String> getAttributes() {

            return attributes;
        }

        public void setAttributes(Map<String, String> attributes) {

            this.attributes = attributes;
        }

        @Override
        public String getType() {

            return "FEDERATED";
        }
    }

    /**
     * Mirrors AuthenticatedUser.
     */
    public static class TestAuthenticatedUser implements Serializable {

        private String userName;
        private String tenantDomain;
        private String userStoreDomain;
        private boolean federatedUser;
        private Map<String, String> userAttributes = new HashMap<>();
        private TestCredential credential;

        public String getUserName() {

            return userName;
        }

        public void setUserName(String userName) {

            this.userName = userName;
        }

        public String getTenantDomain() {

            return tenantDomain;
        }

        public void setTenantDomain(String tenantDomain) {

            this.tenantDomain = tenantDomain;
        }

        public String getUserStoreDomain() {

            return userStoreDomain;
        }

        public void setUserStoreDomain(String userStoreDomain) {

            this.userStoreDomain = userStoreDomain;
        }

        public boolean isFederatedUser() {

            return federatedUser;
        }

        public void setFederatedUser(boolean federatedUser) {

            this.federatedUser = federatedUser;
        }

        public Map<String, String> getUserAttributes() {

            return userAttributes;
        }

        public void setUserAttributes(Map<String, String> userAttributes) {

            this.userAttributes = userAttributes;
        }

        public TestCredential getCredential() {

            return credential;
        }

        public void setCredential(TestCredential credential) {

            this.credential = credential;
        }
    }

    /**
     * Mirrors AuthHistory entries.
     */
    public static class TestAuthHistory implements Serializable {

        private String authenticatorName;
        private String idpName;
        private long timestamp;

        public TestAuthHistory() {

        }

        public TestAuthHistory(String authenticatorName, String idpName, long timestamp) {

            this.authenticatorName = authenticatorName;
            this.idpName = idpName;
            this.timestamp = timestamp;
        }

        public String getAuthenticatorName() {

            return authenticatorName;
        }

        public String getIdpName() {

            return idpName;
        }

        public long getTimestamp() {

            return timestamp;
        }
    }

    /**
     * Mirrors StepConfig.
     */
    public static class TestStepConfig implements Serializable {

        private int order;
        private String authenticatedIdP;
        private List<String> authenticatorList = new ArrayList<>();
        private boolean completed;
        private TestAuthenticatedUser authenticatedUser;

        public int getOrder() {

            return order;
        }

        public void setOrder(int order) {

            this.order = order;
        }

        public String getAuthenticatedIdP() {

            return authenticatedIdP;
        }

        public void setAuthenticatedIdP(String authenticatedIdP) {

            this.authenticatedIdP = authenticatedIdP;
        }

        public List<String> getAuthenticatorList() {

            return authenticatorList;
        }

        public void setAuthenticatorList(List<String> authenticatorList) {

            this.authenticatorList = authenticatorList;
        }

        public boolean isCompleted() {

            return completed;
        }

        public void setCompleted(boolean completed) {

            this.completed = completed;
        }

        public TestAuthenticatedUser getAuthenticatedUser() {

            return authenticatedUser;
        }

        public void setAuthenticatedUser(TestAuthenticatedUser authenticatedUser) {

            this.authenticatedUser = authenticatedUser;
        }
    }

    /**
     * Mirrors SequenceConfig; the step map is keyed by boxed integers.
     */
    public static class TestSequenceConfig implements Serializable {

        private String applicationId;
        private Map<Integer, TestStepConfig> stepMap = new HashMap<>();
        private TestAuthenticatedUser authenticatedUser;
        private Set<String> requestedClaims = new HashSet<>();

        public String getApplicationId() {

            return applicationId;
        }

        public void setApplicationId(String applicationId) {

            this.applicationId = applicationId;
        }

        public Map<Integer, TestStepConfig> getStepMap() {

            return stepMap;
        }

        public void setStepMap(Map<Integer, TestStepConfig> stepMap) {

            this.stepMap = stepMap;
        }

        public TestAuthenticatedUser getAuthenticatedUser() {

            return authenticatedUser;
        }

        public void setAuthenticatedUser(TestAuthenticatedUser authenticatedUser) {

            this.authenticatedUser = authenticatedUser;
        }

        public Set<String> getRequestedClaims() {

            return requestedClaims;
        }

        public void setRequestedClaims(Set<String> requestedClaims) {

            this.requestedClaims = requestedClaims;
        }
    }

    /**
     * Root of the graph, mirroring AuthenticationContext.
     */
    public static class TestSessionContext implements Serializable {

        private String sessionId;
        private String contextIdentifier;
        private AuthStatus status;
        private Map<String, Object> parameters = new HashMap<>();
        private TestSequenceConfig sequenceConfig;
        private List<TestAuthHistory> authHistory = new ArrayList<>();
        private TestSessionContext previousContext;
        private byte[] serializedBlob;
        private Date createdAt;
        private transient String cachedSecret;

        public String getSessionId() {

            return sessionId;
        }

        public void setSessionId(String sessionId) {

            this.sessionId = sessionId;
        }

        public String getContextIdentifier() {

            return contextIdentifier;
        }

        public void setContextIdentifier(String contextIdentifier) {

            this.contextIdentifier = contextIdentifier;
        }

        public AuthStatus getStatus() {

            return status;
        }

        public void setStatus(AuthStatus status) {

            this.status = status;
        }

        public Map<String, Object> getParameters() {

            return parameters;
        }

        public void setParameters(Map<String, Object> parameters) {

            this.parameters = parameters;
        }

        public TestSequenceConfig getSequenceConfig() {

            return sequenceConfig;
        }

        public void setSequenceConfig(TestSequenceConfig sequenceConfig) {

            this.sequenceConfig = sequenceConfig;
        }

        public List<TestAuthHistory> getAuthHistory() {

            return authHistory;
        }

        public void setAuthHistory(List<TestAuthHistory> authHistory) {

            this.authHistory = authHistory;
        }

        public TestSessionContext getPreviousContext() {

            return previousContext;
        }

        public void setPreviousContext(TestSessionContext previousContext) {

            this.previousContext = previousContext;
        }

        public byte[] getSerializedBlob() {

            return serializedBlob;
        }

        public void setSerializedBlob(byte[] serializedBlob) {

            this.serializedBlob = serializedBlob;
        }

        public Date getCreatedAt() {

            return createdAt;
        }

        public void setCreatedAt(Date createdAt) {

            this.createdAt = createdAt;
        }

        public String getCachedSecret() {

            return cachedSecret;
        }

        public void setCachedSecret(String cachedSecret) {

            this.cachedSecret = cachedSecret;
        }
    }
}
