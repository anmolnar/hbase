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
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.security.auth.AuthenticateCallbackHandler;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerExtensionsValidatorCallback;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerLoginModule;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerValidatorCallback;
import org.apache.hadoop.hbase.security.oauthbearer.Utils;
import org.apache.hadoop.util.Time;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@InterfaceAudience.Public
public class OAuthBearerSignedJwtValidatorCallbackHandler implements AuthenticateCallbackHandler {
  private static final Logger LOG =
    LoggerFactory.getLogger(OAuthBearerSignedJwtValidatorCallbackHandler.class);
  private static final String OPTION_PREFIX = "hbase.security.oauth.jwt.";
  private static final String JWKS_URL = OPTION_PREFIX + "jwks.url";
  private static final String JWKS_FILE = OPTION_PREFIX + "jwks.file";
  private static final String PRINCIPAL_CLAIM_NAME_OPTION = OPTION_PREFIX + "principalclaim";
  private static final String SCOPE_CLAIM_NAME_OPTION = OPTION_PREFIX + "scopeclaim";
  private static final String REQUIRED_SCOPE_OPTION = OPTION_PREFIX + "requiredscope";
  private static final String ALLOWABLE_CLOCK_SKEW_MILLIS_OPTION =
    OPTION_PREFIX + "allowableclockskewms";
  private Configuration hBaseConfiguration;
  private JWKSet jwkSet;
  private boolean configured = false;

  @Override
  public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
    if (!configured) {
      throw new RuntimeException(
        "OAuthBearerSignedJwtValidatorCallbackHandler handler be configured first.");
    }

    for (Callback callback : callbacks) {
      if (callback instanceof OAuthBearerValidatorCallback) {
        OAuthBearerValidatorCallback validationCallback = (OAuthBearerValidatorCallback) callback;
        try {
          handleCallback(validationCallback);
        } catch (OAuthBearerIllegalTokenException e) {
          LOG.error("Signed JWT token validation error: {}", e.getMessage());
          OAuthBearerValidationResult failureReason = e.reason();
          String failureScope = failureReason.failureScope();
          validationCallback.error(failureScope != null ? "insufficient_scope" : "invalid_token",
            failureScope, failureReason.failureOpenIdConfig());
        }
      } else if (callback instanceof OAuthBearerExtensionsValidatorCallback) {
        OAuthBearerExtensionsValidatorCallback extensionsCallback =
          (OAuthBearerExtensionsValidatorCallback) callback;
        extensionsCallback.inputExtensions().map().forEach((extensionName, v) ->
          extensionsCallback.valid(extensionName));
      } else {
        throw new UnsupportedCallbackException(callback);
      }
    }
  }

  @Override public void configure(Configuration configs, String saslMechanism,
    Map<String, String> saslProps) {
    if (!OAuthBearerLoginModule.OAUTHBEARER_MECHANISM.equals(saslMechanism)) {
      throw new IllegalArgumentException(
        String.format("Unexpected SASL mechanism: %s", saslMechanism));
    }

    this.hBaseConfiguration = configs;

    try {
      loadJwkSet();
    } catch (IOException | ParseException e) {
      throw new RuntimeException("Unable to initialize JWK Set", e);
    }

    configured = true;
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
    String principalClaimNameValue = hBaseConfiguration.get(PRINCIPAL_CLAIM_NAME_OPTION);
    return Utils.isBlank(principalClaimNameValue) ? "sub" : principalClaimNameValue.trim();
  }

  private String scopeClaimName() {
    String scopeClaimNameValue = hBaseConfiguration.get(SCOPE_CLAIM_NAME_OPTION);
    return Utils.isBlank(scopeClaimNameValue) ? "scope" : scopeClaimNameValue.trim();
  }

  private List<String> requiredScope() {
    String requiredSpaceDelimitedScope = hBaseConfiguration.get(REQUIRED_SCOPE_OPTION);
    return Utils.isBlank(requiredSpaceDelimitedScope)
      ? Collections.emptyList()
      : OAuthBearerScopeUtils.parseScope(requiredSpaceDelimitedScope.trim());
  }

  private int allowableClockSkewMs() {
    String allowableClockSkewMsValue = hBaseConfiguration.get(ALLOWABLE_CLOCK_SKEW_MILLIS_OPTION);
    int allowableClockSkewMs = 0;
    try {
      allowableClockSkewMs = Utils.isBlank(allowableClockSkewMsValue)
        ? 0 : Integer.parseInt(allowableClockSkewMsValue.trim());
    } catch (NumberFormatException e) {
      throw new OAuthBearerConfigException(e.getMessage(), e);
    }
    if (allowableClockSkewMs < 0) {
      throw new OAuthBearerConfigException(
        String.format("Allowable clock skew millis must not be negative: %s",
          allowableClockSkewMsValue));
    }
    return allowableClockSkewMs;
  }

  private void loadJwkSet() throws IOException, ParseException {
    String jwksFile = hBaseConfiguration.get(JWKS_FILE);
    String jwksUrl = hBaseConfiguration.get(JWKS_URL);

    if (Utils.isBlank(jwksFile) && Utils.isBlank(jwksUrl)) {
      throw new RuntimeException("Failed to initialize JWKS db. "
        + JWKS_FILE + " or " + JWKS_URL + " must be specified in the config.");
    }

    if (!Utils.isBlank(jwksFile)) {
      this.jwkSet = JWKSet.load(new File(jwksFile));
      LOG.debug("JWKS db initialized from file: {}", jwksFile);
      return;
    }

    this.jwkSet = JWKSet.load(new URL(jwksUrl));
    LOG.debug("JWKS db initialized from URL: {}", jwksUrl);
  }
}
