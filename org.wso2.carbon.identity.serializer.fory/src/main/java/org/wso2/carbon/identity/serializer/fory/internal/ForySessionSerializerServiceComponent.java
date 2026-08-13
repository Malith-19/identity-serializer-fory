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

package org.wso2.carbon.identity.serializer.fory.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionSerializer;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.serializer.fory.ForySessionSerializer;

/**
 * Fory Serialization service component.
 */
@Component(
        name = "identity.serializer.fory",
        immediate = true
)
public class ForySessionSerializerServiceComponent {

    private static final Log LOG = LogFactory.getLog(ForySessionSerializerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            BundleContext bundleContext = ctxt.getBundleContext();
            bundleContext.registerService(SessionSerializer.class.getName(), new ForySessionSerializer(), null);
            if (LOG.isDebugEnabled()) {
                LOG.debug("Apache Fory Session Serializer is activated.");
            }
        } catch (Throwable e) {
            LOG.error("Error occurred while activating the Apache Fory Session Serializer. Hence the performance of " +
                    "session persistence will be impaired.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (LOG.isDebugEnabled()) {
            LOG.debug("Apache Fory Session Serializer is deactivated.");
        }
    }

    @Reference(
            name = "identityCoreInitializedEventService",
            service = IdentityCoreInitializedEvent.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityCoreInitializedEventService")
    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

        /* Reference IdentityCoreInitializedEvent service to guarantee that this component waits until identity core
           is started. The serializer reads Fory.EnableCompatibilityMode through IdentityUtil, which returns null
           until identity core has populated the configuration. */
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {

        /* Reference IdentityCoreInitializedEvent service to guarantee that this component waits until identity core
           is started. */
    }
}
