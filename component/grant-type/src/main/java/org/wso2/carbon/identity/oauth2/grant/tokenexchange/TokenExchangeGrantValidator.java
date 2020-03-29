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

import org.apache.oltu.oauth2.common.OAuth;
import org.apache.oltu.oauth2.common.validators.AbstractValidator;

import javax.servlet.http.HttpServletRequest;

/**
 * This is to verify if all the require parameters are there in the request.
 * Required parameter for 'Delegation', 'actor_token_type' will not be checked here
 * as it is only required if 'actor_token' is present in the request.
 */
public class TokenExchangeGrantValidator extends AbstractValidator<HttpServletRequest> {

    public TokenExchangeGrantValidator() {
        requiredParams.add(OAuth.OAUTH_GRANT_TYPE);
        requiredParams.add(TokenExchangeConstants.SUBJECT_TOKEN);
        requiredParams.add(TokenExchangeConstants.SUBJECT_TOKEN_TYPE);
    }
}
