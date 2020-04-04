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

public class TokenExchangeConstants {

    public static final String RESOURCE = "resource";
    public static final String AUDIENCE = "audience";
    public static final String REQUESTED_TOKEN_TYPE = "requested_token_type";
    public static final String SUBJECT_TOKEN = "subject_token";
    public static final String SUBJECT_TOKEN_TYPE = "subject_token_type";
    public static final String ACTOR_TOKEN = "actor_token";
    public static final String ACTOR_TOKEN_TYPE = "actor_token_type";
    public static final String ISSUED_TOKEN_TYPE = "issued_token_type";
    public static final String TOKEN_TYPE = "token_type";
    public static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    static class ActorTokenTypes {
        public static final String ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token";
        public static final String REFRESH_TOKEN = "urn:ietf:params:oauth:token-type:refresh_token";
        public static final String ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
        // TODO Commented as we don't support yet. Make extensible
        // public static final String SAML2 = "urn:ietf:params:oauth:token-type:saml2";
        // TODO Check best practise here
        public static final String[] actorTokenTypesArray = {ACCESS_TOKEN, REFRESH_TOKEN, ID_TOKEN};
    }
}
