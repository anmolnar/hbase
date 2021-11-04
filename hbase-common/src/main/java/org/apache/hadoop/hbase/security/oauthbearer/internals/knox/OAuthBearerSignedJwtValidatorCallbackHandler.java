/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hbase.security.oauthbearer.internals.knox;

import com.nimbusds.jose.jwk.JWKSet;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import org.apache.hadoop.hbase.security.auth.AuthenticateCallbackHandler;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerExtensionsValidatorCallback;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.hadoop.hbase.security.oauthbearer.Utils;
import org.apache.hadoop.util.Time;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@InterfaceAudience.Public
public class OAuthBearerSignedJwtValidatorCallbackHandler implements AuthenticateCallbackHandler {
  private static final Logger LOG = LoggerFactory.getLogger(OAuthBearerSignedJwtValidatorCallbackHandler.class);
  private static final String OPTION_PREFIX = "signedJwtValidator";
  private static final String PRINCIPAL_CLAIM_NAME_OPTION = OPTION_PREFIX + "PrincipalClaimName";
  private static final String SCOPE_CLAIM_NAME_OPTION = OPTION_PREFIX + "ScopeClaimName";
  private static final String REQUIRED_SCOPE_OPTION = OPTION_PREFIX + "RequiredScope";
  private static final String ALLOWABLE_CLOCK_SKEW_MILLIS_OPTION = OPTION_PREFIX + "AllowableClockSkewMs";
  private final JWKSet jwkSet;

  public OAuthBearerSignedJwtValidatorCallbackHandler(JWKSet jwkSet) {
    this.jwkSet = jwkSet;
  }

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
    for (Callback callback : callbacks) {
      if (callback instanceof OAuthBearerValidatorCallback) {
        OAuthBearerValidatorCallback validationCallback = (OAuthBearerValidatorCallback) callback;
        try {
          handleCallback(validationCallback);
        } catch (OAuthBearerIllegalTokenException e) {
          OAuthBearerValidationResult failureReason = e.reason();
          String failureScope = failureReason.failureScope();
          validationCallback.error(failureScope != null ? "insufficient_scope" : "invalid_token",
            failureScope, failureReason.failureOpenIdConfig());
        }
      } else if (callback instanceof OAuthBearerExtensionsValidatorCallback) {
        OAuthBearerExtensionsValidatorCallback extensionsCallback = (OAuthBearerExtensionsValidatorCallback) callback;
        extensionsCallback.inputExtensions().map().forEach((extensionName, v) -> extensionsCallback.valid(extensionName));
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }

  @Override public void configure(Map<String, ?> configs, String saslMechanism,
    List<AppConfigurationEntry> jaasConfigEntries) {
  }

  @Override
  public void close() {
    // empty
  }

  private void handleCallback(OAuthBearerValidatorCallback callback) {
    String tokenValue = callback.tokenValue();
    if (tokenValue == null) {
      throw new IllegalArgumentException("Callback missing required token value");
    }
    String principalClaimName = principalClaimName();
    String scopeClaimName = scopeClaimName();
    List<String> requiredScope = requiredScope();
    int allowableClockSkewMs = allowableClockSkewMs();
    OAuthBearerSignedJwt signedJwt =
      new OAuthBearerSignedJwt(tokenValue, principalClaimName, scopeClaimName, jwkSet);
    long now = Time.monotonicNow();
    OAuthBearerValidationUtils
      .validateClaimForExistenceAndType(signedJwt, true, principalClaimName, String.class)
      .throwExceptionIfFailed();
    OAuthBearerValidationUtils.validateIssuedAt(signedJwt, false, now, allowableClockSkewMs)
      .throwExceptionIfFailed();
    OAuthBearerValidationUtils.validateExpirationTime(signedJwt, now, allowableClockSkewMs)
      .throwExceptionIfFailed();
    OAuthBearerValidationUtils.validateTimeConsistency(signedJwt).throwExceptionIfFailed();
    OAuthBearerValidationUtils.validateScope(signedJwt, requiredScope).throwExceptionIfFailed();
    LOG.info("Successfully validated token with principal {}: {}", signedJwt.principalName(),
      signedJwt.claims());
    callback.token(signedJwt);
  }

  private String principalClaimName() {
    String principalClaimNameValue = option(PRINCIPAL_CLAIM_NAME_OPTION);
    return Utils.isBlank(principalClaimNameValue) ? "sub" : principalClaimNameValue.trim();
  }

  private String scopeClaimName() {
    String scopeClaimNameValue = option(SCOPE_CLAIM_NAME_OPTION);
    return Utils.isBlank(scopeClaimNameValue) ? "scope" : scopeClaimNameValue.trim();
  }

  private List<String> requiredScope() {
    String requiredSpaceDelimitedScope = option(REQUIRED_SCOPE_OPTION);
    return Utils.isBlank(requiredSpaceDelimitedScope) ? Collections.emptyList() : OAuthBearerScopeUtils.parseScope(requiredSpaceDelimitedScope.trim());
  }

  private int allowableClockSkewMs() {
    String allowableClockSkewMsValue = option(ALLOWABLE_CLOCK_SKEW_MILLIS_OPTION);
    int allowableClockSkewMs = 0;
    try {
      allowableClockSkewMs = Utils.isBlank(allowableClockSkewMsValue) ? 0 : Integer.parseInt(allowableClockSkewMsValue.trim());
    } catch (NumberFormatException e) {
      throw new OAuthBearerConfigException(e.getMessage(), e);
    }
    if (allowableClockSkewMs < 0) {
      throw new OAuthBearerConfigException(
        String.format("Allowable clock skew millis must not be negative: %s", allowableClockSkewMsValue));
    }
    return allowableClockSkewMs;
  }

  private String option(String key) {
    return "";
  }
}
