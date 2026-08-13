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

import org.apache.fory.Fory;
import org.apache.fory.ThreadSafeFory;
import org.apache.fory.config.Language;
import org.apache.fory.logging.LogLevel;
import org.apache.fory.logging.LoggerFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.SessionSerializerException;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionSerializer;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.InputStream;
import java.io.ByteArrayInputStream;

/**
 * Implementation of Session Serializer with Apache Fory Serialization library.
 */
public class ForySessionSerializer implements SessionSerializer {

    private static final String FORY_COMPATIBILITY_MODE_PROPERTY = "Fory.EnableCompatibilityMode";
    private static final boolean DEFAULT_COMPATIBILITY_MODE_ENABLED = true;
    private static final ThreadSafeFory fory;

    static {
        // Set the fory related logs level to WARN.
        LoggerFactory.setLogLevel(LogLevel.WARN_LEVEL);

        fory = Fory.builder()
                .withLanguage(Language.JAVA)
                .withRefTracking(true)      // Handles circular references in big sessions.
                .requireClassRegistration(false) // Safety net for dynamic class loading.
                .withCompatible(isCompatibilityModeEnabled())
                .withCodegen(true)
                .withStringCompressed(true)
                .withNumberCompressed(true)
                .withLongCompressed(true)
                .withIntArrayCompressed(true)
                .withLongArrayCompressed(true)
                .withAsyncCompilation(true)
                .withClassLoader(ForySessionSerializer.class.getClassLoader())
                .buildThreadSafeFory();

        registerClasses();
    }

    /**
     * Checks whether Fory's compatible mode is enabled, which lets sessions written with one class
     * shape be read back after fields are added or removed. Defaults to enabled when the
     * Fory.EnableCompatibilityMode property is not configured.
     *
     * @return true if compatible mode should be used.
     */
    private static boolean isCompatibilityModeEnabled() {

        String configuredValue = IdentityUtil.getProperty(FORY_COMPATIBILITY_MODE_PROPERTY);
        if (configuredValue == null) {
            return DEFAULT_COMPATIBILITY_MODE_ENABLED;
        }
        return Boolean.parseBoolean(configuredValue);
    }

    private static void registerClasses() {

        /*
            IMPORTANT: Never change these ID numbers once data has been persisted to the DB.
            Standard Java natives (String, ArrayList, etc.) are omitted to utilize Fory's
            internal optimized IDs.
         */

        // --- WSO2 Authentication Framework Models ---
        fory.register(org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext.class, 100);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser.class, 101);
        fory.register(org.wso2.carbon.identity.application.common.model.ClaimMapping.class, 102);
        fory.register(org.wso2.carbon.identity.application.common.model.Claim.class, 103);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.context.AuthHistory.class, 104);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.context.SessionAuthHistory.class, 105);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.context.AcrRule.class, 106);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.context.TransientObjectWrapper.class, 107);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig.class, 108);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig.class, 109);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig.class, 110);

        // --- Optimized Session Models ---
        /* Produced by AuthenticationContextLoader/SessionContextLoader in place of the full
        objects when a session is persisted. */
        fory.register(org.wso2.carbon.identity.application.authentication.framework.context.OptimizedSessionContext.class, 111);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.model.OptimizedAuthenticatedIdPData.class, 112);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.config.model.OptimizedApplicationConfig.class, 113);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.config.model.OptimizedAuthenticatorConfig.class, 114);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.config.model.OptimizedSequenceConfig.class, 115);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.config.model.OptimizedStepConfig.class, 116);

        // --- WSO2 Cache Entry Wrappers ---
        fory.register(org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationContextCacheEntry.class, 117);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.cache.SessionContextCacheEntry.class, 118);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationResultCacheEntry.class, 119);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest.class, 120);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult.class, 121);

        // --- WSO2 OAuth & OIDC Specifics ---
        fory.register(org.wso2.carbon.identity.oauth.cache.SessionDataCacheEntry.class, 122);
        fory.register(org.wso2.carbon.identity.oauth.cache.AuthorizationGrantCacheEntry.class, 123);
        fory.register(org.wso2.carbon.identity.oauth2.model.OAuth2Parameters.class, 124);
        fory.register(org.wso2.carbon.identity.oidc.session.OIDCSessionState.class, 125);
        fory.register(org.wso2.carbon.identity.oidc.session.cache.OIDCSessionParticipantCacheEntry.class, 126);

        // --- WSO2 Authentication Framework Models (contd.) ---
        fory.register(org.wso2.carbon.identity.application.authentication.framework.config.model.ApplicationConfig.class, 127);
        fory.register(org.wso2.carbon.identity.application.authentication.framework.model.ImpersonatedUser.class, 128);

        // --- WSO2 Service Provider & Identity Provider Models ---
        /* Reached through AuthenticationContext -> SequenceConfig -> ApplicationConfig, so the whole
        ServiceProvider graph ends up in the serialized session. */
        fory.register(org.wso2.carbon.identity.application.common.model.ServiceProvider.class, 129);
        fory.register(org.wso2.carbon.identity.application.common.model.ServiceProviderProperty.class, 130);
        fory.register(org.wso2.carbon.identity.application.common.model.SpTrustedAppMetadata.class, 131);
        fory.register(org.wso2.carbon.identity.application.common.model.AssociatedRolesConfig.class, 132);
        fory.register(org.wso2.carbon.identity.application.common.model.RoleV2.class, 133);
        fory.register(org.wso2.carbon.identity.application.common.model.ClaimConfig.class, 134);
        fory.register(org.wso2.carbon.identity.application.common.model.ClientAttestationMetaData.class, 135);
        fory.register(org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig.class, 136);
        fory.register(org.wso2.carbon.identity.application.common.model.InboundProvisioningConfig.class, 137);
        fory.register(org.wso2.carbon.identity.application.common.model.LocalAndOutboundAuthenticationConfig.class, 138);
        fory.register(org.wso2.carbon.identity.application.common.model.LocalAuthenticatorConfig.class, 139);
        fory.register(org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig.class, 140);
        fory.register(org.wso2.carbon.identity.application.common.model.IdentityProvider.class, 141);
        fory.register(org.wso2.carbon.identity.application.common.model.Property.class, 142);
        fory.register(org.wso2.carbon.identity.application.common.model.User.class, 143);
        fory.register(org.wso2.carbon.identity.application.common.model.script.AuthenticationScriptConfig.class, 144);

        // --- WSO2 OAuth & OIDC Specifics (contd.) ---
        fory.register(org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext.class, 145);
        fory.register(org.wso2.carbon.identity.openidconnect.model.RequestObject.class, 146);
        fory.register(org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetails.class, 147);
        fory.register(org.wso2.carbon.identity.oauth.rar.model.AuthorizationDetail.class, 148);
    }

    @Override
    public InputStream serializeSessionObject(Object o) throws SessionSerializerException {

        try {
            byte[] bytes = fory.serialize(o);
            return new ByteArrayInputStream(bytes);
        } catch (Exception e) {
            throw new SessionSerializerException("Error while serializing the session object using Fory.", e);
        }
    }

    @Override
    public Object deSerializeSessionObject(InputStream inputStream) throws SessionSerializerException {

        try {
            return fory.deserialize(inputStream.readAllBytes());
        } catch (Exception e) {
            throw new SessionSerializerException("Error while de-serializing the session object using Fory.", e);
        }
    }
}
