package org.wso2.carbon.identity.application.authentication.framework.custom;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.AuthenticationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.handler.request.impl.DefaultAuthenticationRequestHandler;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;

public class CustomAuthenticationRequestHandler extends DefaultAuthenticationRequestHandler
        implements AuthenticationRequestHandler {

    private static final Log log = LogFactory.getLog(CustomAuthenticationRequestHandler.class);
    private static final Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;

    @Override
    protected void sendResponse(HttpServletRequest request, HttpServletResponse response,
                                AuthenticationContext context) throws FrameworkException {
        if (log.isDebugEnabled()) {
            StringBuilder debugMessage = new StringBuilder();
            debugMessage.append("Sending response back to: ");
            debugMessage.append(context.getCallerPath()).append("...\n");
            debugMessage.append(FrameworkConstants.ResponseParams.AUTHENTICATED).append(": ");
            debugMessage.append(String.valueOf(context.isRequestAuthenticated())).append("\n");
            debugMessage.append(FrameworkConstants.ResponseParams.AUTHENTICATED_USER).append(": ");
            if (context.getSequenceConfig().getAuthenticatedUser() != null) {
                debugMessage.append(context.getSequenceConfig().getAuthenticatedUser().getAuthenticatedSubjectIdentifier()).append("\n");
            } else {
                debugMessage.append("No Authenticated User").append("\n");
            }
            debugMessage.append(FrameworkConstants.ResponseParams.AUTHENTICATED_IDPS).append(": ");
            debugMessage.append(context.getSequenceConfig().getAuthenticatedIdPs()).append("\n");
            debugMessage.append(FrameworkConstants.SESSION_DATA_KEY).append(": ");
            debugMessage.append(context.getCallerSessionKey());

            log.debug(debugMessage);
        }

        // TODO rememberMe should be handled by a cookie authenticator. For now rememberMe flag that
        // was set in the login page will be sent as a query param to the calling servlet so it will
        // handle rememberMe as usual.
        String rememberMeParam = "";

        if (context.isRequestAuthenticated() && context.isRememberMe()) {
            rememberMeParam = rememberMeParam + "chkRemember=on";
        }

        // if request is not authenticated populate error information sent from authenticators/handlers
        if (!context.isRequestAuthenticated()) {
            populateErrorInformation(request, response, context);
        }

        // redirect to the caller
        String redirectURL;
//        String commonauthCallerPath = context.getCallerPath();
        String commonauthCallerPath = IdentityUtil.getProperty(CustomAuthenticationRequestHandlerConstants.OAUTH +
                "." + CustomAuthenticationRequestHandlerConstants.OAUTH2_AUTHZ_URL);

        try {
            String queryParamsString = "";
            if (context.getCallerSessionKey() != null) {
                queryParamsString = FrameworkConstants.SESSION_DATA_KEY + "=" +
                        URLEncoder.encode(context.getCallerSessionKey(), "UTF-8");
            }

            if (StringUtils.isNotEmpty(rememberMeParam)) {
                queryParamsString += "&" + rememberMeParam;
            }
            redirectURL = FrameworkUtils.appendQueryParamsStringToUrl(commonauthCallerPath, queryParamsString);

            response.sendRedirect(redirectURL);
        } catch (IOException e) {
            throw new FrameworkException(e.getMessage(), e);
        }
    }
}
