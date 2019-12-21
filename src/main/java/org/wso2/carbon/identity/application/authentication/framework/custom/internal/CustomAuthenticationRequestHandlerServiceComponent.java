package org.wso2.carbon.identity.application.authentication.framework.custom.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.wso2.carbon.identity.application.authentication.framework.custom.CustomAuthenticationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AuthenticationRequestHandler;

@Component(
        name = "org.wso2.carbon.identity.application.authentication.framework.custom.component",
        immediate = true
)
public class CustomAuthenticationRequestHandlerServiceComponent {

    private static Log log = LogFactory.getLog(CustomAuthenticationRequestHandlerServiceComponent.class);

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            CustomAuthenticationRequestHandler customAuthenticationRequestHandler =
                    new CustomAuthenticationRequestHandler();
            ctxt.getBundleContext().registerService(AuthenticationRequestHandler.class.getName(),
                    customAuthenticationRequestHandler, null);
            if (log.isDebugEnabled()) {
                log.debug("Custom Authentication Request Handler bundle is activated");
            }
        } catch (Throwable e) {
            log.fatal("Error while activating the Custom Authentication Request Handler", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("Custom Authentication Request Handler bundle is deactivated");
        }
    }

}
