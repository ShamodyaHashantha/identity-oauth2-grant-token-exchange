/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.grant.tokenexchange;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

public class TokenExchangeGrantHandler extends AbstractAuthorizationGrantHandler {
    private static final Log log = LogFactory.getLog(TokenExchangeGrantHandler.class);

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {
        super.validateGrant(tokReqMsgCtx);
        OAuth2AccessTokenReqDTO tokenReq = tokReqMsgCtx.getOauth2AccessTokenReqDTO();
        boolean delegation = isDelegationRequest(tokenReq);
        return true;
    }

    /**
     * This method checks if the received exchange request is a delegation request.
     * Delegation requests must have 'actor_token' and 'actor_token_type' parameters.
     * @param tokenReq
     * @return
     * @throws IdentityOAuth2Exception
     */
    private boolean isDelegationRequest(OAuth2AccessTokenReqDTO tokenReq) throws IdentityOAuth2Exception {
        RequestParameter[] parameters = tokenReq.getRequestParameters();
        boolean actorTokenFound = false;
        boolean actorTokenTypeFound = false;
        if (parameters != null) {
            for (int i = 0; i < parameters.length; i++) {
                // TODO check if this is the best approach.
                // tokenReq.getRequestParameters() is a String[] and each element is a String[]. Hence the hassle.
                // Considered the param value should present as the first element of the value array.
                // Check if 'actor_token' presents
                if (!actorTokenFound && TokenExchangeConstants.ACTOR_TOKEN.equals(parameters[i].getKey())
                        && parameters[i].getValue() != null
                        && parameters[i].getValue().length > 0
                        && StringUtils.isNotEmpty(parameters[i].getValue()[0])) {
                    actorTokenFound = true;
                    log.debug("Actor token present in the token request : " + parameters[i].getValue()[0]);
                }

                // Check if 'actor_token_type' presents
                if (!actorTokenTypeFound && TokenExchangeConstants.ACTOR_TOKEN_TYPE.equals(parameters[i].getKey())
                        && parameters[i].getValue() != null
                        && parameters[i].getValue().length > 0
                        && StringUtils.isNotEmpty(parameters[i].getValue()[0])) {
                    actorTokenTypeFound = true;
                    String actorTokenType = parameters[i].getValue()[0].trim();
                    log.debug("Actor token type present in the request : " + actorTokenType);
                    isValidActorTokenType(actorTokenType);
                }
            }
        }
        // If 'actor_token' presents, 'actor_token_type' must present.
        if (actorTokenFound && !actorTokenTypeFound) {
            throw new IdentityOAuth2Exception(" Actor token type parameter not found in the request.");
        }
        return actorTokenFound && actorTokenTypeFound;
    }

    private boolean isValidActorTokenType(String actorTokenType) throws IdentityOAuth2Exception {
        for (String type : TokenExchangeConstants.ActorTokenTypes.actorTokenTypesArray) {
            if (type.equals(actorTokenType)){
                return true;
            }
        }
        throw new IdentityOAuth2Exception("Invalid actor token type : " + actorTokenType);
    }
}
