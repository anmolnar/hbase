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
package org.apache.hadoop.hbase.security.provider;

import java.util.Collection;
import java.util.Optional;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.util.Pair;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.yetus.audience.InterfaceAudience;

@InterfaceAudience.Private
public class OAuthBearerSaslProviderSelector extends BuiltInProviderSelector {

  private final Text OAUTHBEARER_TOKEN_KIND_TEXT =
    new Text(OAuthBearerSaslAuthenticationProvider.JWT_TOKEN_TYPE);
  private OAuthBearerSaslClientAuthenticationProvider oauthbearer;

  @Override public void configure(Configuration conf,
    Collection<SaslClientAuthenticationProvider> providers) {
    super.configure(conf, providers);

    this.oauthbearer = (OAuthBearerSaslClientAuthenticationProvider) providers.stream()
      .filter((p) -> p instanceof OAuthBearerSaslClientAuthenticationProvider)
      .findFirst()
      .orElseThrow(() -> new RuntimeException(
        "OAuthBearerSaslClientAuthenticationProvider not loaded"));
  }

  @Override
  public Pair<SaslClientAuthenticationProvider, Token<? extends TokenIdentifier>> selectProvider(
    String clusterId, User user) {
    Pair<SaslClientAuthenticationProvider, Token<? extends TokenIdentifier>> pair =
      super.selectProvider(clusterId, user);

    Optional<Token<?>> optional = user.getTokens().stream()
      .filter((t) -> OAUTHBEARER_TOKEN_KIND_TEXT.equals(t.getKind()))
      .findFirst();
    if (optional.isPresent()) {
      return new Pair<>(oauthbearer, optional.get());
    }

    return pair;
  }
}
