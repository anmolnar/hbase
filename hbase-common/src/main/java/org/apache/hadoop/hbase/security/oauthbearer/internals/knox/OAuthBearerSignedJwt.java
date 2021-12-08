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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerToken;
import org.apache.hadoop.hbase.security.oauthbearer.Utils;
import org.apache.yetus.audience.InterfaceAudience;

/**
 * Signed JWT implementation for OAuth Bearer authentication mech of SASL.
 *
 * This class is based on Kafka's Unsecured JWS token implementation.
 */
@InterfaceAudience.Public
public class OAuthBearerSignedJwt implements OAuthBearerToken {
  private final String compactSerialization;
  private final JWTClaimsSet claims;
  private final long lifetime;
  private final JWKSet jwkSet;
  private final int maxClockSkewSeconds;
  private final String requiredAudience;

  /**
   * Constructor with the given audience and maximum clock skew
   *
   * @param compactSerialization
   *            the compact serialization to parse as a signed JWT
   * @param requiredAudience
   *            the audience which this JWT should be issued to
   * @param jwkSet
   *            the key set which the signature of this JWT should be verified with
   */
  public OAuthBearerSignedJwt(String compactSerialization, String requiredAudience, JWKSet jwkSet) {
    this(compactSerialization, requiredAudience, jwkSet, 0);
  }

  /**
   * Constructor with the given audience and maximum clock skew
   *
   * @param compactSerialization
   *            the compact serialization to parse as a signed JWT
   * @param requiredAudience
   *            the audience which this JWT should be issued to
   * @param jwkSet
   *            the key set which the signature of this JWT should be verified with
   * @param maxClockSkewSeconds
   *            maximum allowed clock skew in seconds
   * @throws OAuthBearerIllegalTokenException
   *             if the compact serialization is not a valid JWT
   *             (meaning it did not have 3 dot-separated Base64URL sections
   *             with a digital signature; or the header or claims
   *             either are not valid Base 64 URL encoded values or are not JSON
   *             after decoding; or the mandatory '{@code alg}' header value is
   *             missing)
   */
  public OAuthBearerSignedJwt(String compactSerialization, String requiredAudience, JWKSet jwkSet,
    int maxClockSkewSeconds)
    throws OAuthBearerIllegalTokenException {
    this.jwkSet = jwkSet;
    this.maxClockSkewSeconds = maxClockSkewSeconds;
    try {
      this.compactSerialization = Objects.requireNonNull(compactSerialization);
      this.requiredAudience = requiredAudience;
      this.claims = validateToken(compactSerialization);

      Number expirationTimeSeconds = expirationTime();
      if (expirationTimeSeconds == null) {
        throw new OAuthBearerIllegalTokenException(
          OAuthBearerValidationResult.newFailure("No expiration time in JWT"));
      }
      lifetime = convertClaimTimeInSecondsToMs(expirationTimeSeconds);
      String principalName = claims.getSubject();
      if (Utils.isBlank(principalName)) {
        throw new OAuthBearerIllegalTokenException(OAuthBearerValidationResult
          .newFailure("No principal name in JWT claim"));
      }
    } catch (ParseException | BadJOSEException | JOSEException e) {
      throw new OAuthBearerIllegalTokenException(
        OAuthBearerValidationResult.newFailure("Token validation failed: " + e.getMessage()), e);
    }
  }

  @Override
  public String value() {
    return compactSerialization;
  }

  @Override
  public String principalName() {
    return claims.getSubject();
  }

  @Override
  public long lifetimeMs() {
    return lifetime;
  }

  /**
   * Return the JWT Claim Set as a {@code Map}
   *
   * @return the (always non-null but possibly empty) claims
   */
  public Map<String, Object> claims() {
    return claims.getClaims();
  }

  /**
   * Extract a claim of the given type
   *
   * @param claimName
   *            the mandatory JWT claim name
   * @param type
   *            the mandatory type, which must either be String.class,
   *            Number.class, or List.class
   * @return the claim if it exists, otherwise null
   * @throws OAuthBearerIllegalTokenException
   *             if the claim exists but is not the given type
   */
  public <T> T claim(String claimName, Class<T> type) throws OAuthBearerIllegalTokenException {
    Object value = rawClaim(claimName);
    try {
      return Objects.requireNonNull(type).cast(value);
    } catch (ClassCastException e) {
      throw new OAuthBearerIllegalTokenException(
        OAuthBearerValidationResult.newFailure(
          String.format("The '%s' claim was not of type %s: %s",
          claimName, type.getSimpleName(), value.getClass().getSimpleName())));
    }
  }

  /**
   * Extract a claim in its raw form
   *
   * @param claimName
   *            the mandatory JWT claim name
   * @return the raw claim value, if it exists, otherwise null
   */
  public Object rawClaim(String claimName) {
    return claims().get(Objects.requireNonNull(claimName));
  }

  /**
   * Return the
   * <a href="https://tools.ietf.org/html/rfc7519#section-4.1.4">Expiration
   * Time</a> claim
   *
   * @return the <a href=
   *         "https://tools.ietf.org/html/rfc7519#section-4.1.4">Expiration
   *         Time</a> claim if available, otherwise null
   * @throws OAuthBearerIllegalTokenException
   *             if the claim value is the incorrect type
   */
  public Number expirationTime() throws OAuthBearerIllegalTokenException {
    return claims.getExpirationTime().getTime() / 1000L;
  }

  /**
   * Return the
   * <a href="https://tools.ietf.org/html/rfc7519#section-4.1.2">Subject</a> claim
   *
   * @return the <a href=
   *         "https://tools.ietf.org/html/rfc7519#section-4.1.2">Subject</a> claim
   *         if available, otherwise null
   * @throws OAuthBearerIllegalTokenException
   *             if the claim value is the incorrect type
   */
  public String subject() throws OAuthBearerIllegalTokenException {
    return claim("sub", String.class);
  }

  /**
   * Returns the audience of access, as per
   * <a href="https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3">
   *   RFC7519 Section 4.1.3</a>
   *
   * @return the token's (always non-null but potentially empty) expected audience.
   */
  public String audience() {
    return claim("aud", String.class);
  }

  private static long convertClaimTimeInSecondsToMs(Number claimValue) {
    return Math.round(claimValue.doubleValue() * 1000);
  }

  /**
   * This method provides a single method for validating the JWT for use in
   * request processing. It provides for the override of specific aspects of
   * this implementation through submethods used within but also allows for the
   * override of the entire token validation algorithm.
   *
   * @param jwtToken the token to validate
   * @return true if valid
   */
  private JWTClaimsSet validateToken(String jwtToken)
    throws BadJOSEException, JOSEException, ParseException {
    JWT jwt = JWTParser.parse(jwtToken);
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

    Set<String> requiredClaims = new HashSet<>();
    JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder();
    if (!Utils.isBlank(requiredAudience)) {
      requiredClaims.add("aud");
      jwtClaimsSetBuilder.audience(requiredAudience);
    }
    requiredClaims.add("sub");
    DefaultJWTClaimsVerifier<SecurityContext> jwtClaimsSetVerifier =
      new DefaultJWTClaimsVerifier<>(jwtClaimsSetBuilder.build(), requiredClaims);
    jwtClaimsSetVerifier.setMaxClockSkew(maxClockSkewSeconds);

    jwtProcessor.setJWTClaimsSetVerifier(jwtClaimsSetVerifier);

    JWSKeySelector<SecurityContext> keySelector =
      new JWSVerificationKeySelector<>((JWSAlgorithm)jwt.getHeader().getAlgorithm(),
        new ImmutableJWKSet<>(jwkSet));
    jwtProcessor.setJWSKeySelector(keySelector);
    return jwtProcessor.process(jwtToken, null);
  }
}
