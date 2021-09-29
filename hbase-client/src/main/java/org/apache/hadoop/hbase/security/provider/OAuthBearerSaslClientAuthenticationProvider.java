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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.security.SaslUtil;
import org.apache.hadoop.hbase.security.SecurityInfo;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.auth.SaslExtensions;
import org.apache.hadoop.hbase.security.auth.SaslExtensionsCallback;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerToken;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerTokenCallback;
import org.apache.hadoop.hbase.shaded.protobuf.generated.RPCProtos;
import org.apache.hadoop.security.token.Token;
import org.apache.hadoop.security.token.TokenIdentifier;
import org.apache.yetus.audience.InterfaceAudience;

import java.io.IOException;
import java.net.InetAddress;
import java.security.AccessController;
import java.util.Map;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;

@InterfaceAudience.Private
public class OAuthBearerSaslClientAuthenticationProvider extends OAuthBearerSaslAuthenticationProvider
  implements SaslClientAuthenticationProvider {

  @Override
  public SaslClient createClient(Configuration conf, InetAddress serverAddr,
                                 SecurityInfo securityInfo, Token<? extends TokenIdentifier> token, boolean fallbackAllowed,
                                 Map<String, String> saslProps) throws IOException {
    return Sasl.createSaslClient(new String[] { getSaslAuthMethod().getSaslMechanism() }, null,
        null, SaslUtil.SASL_DEFAULT_REALM, saslProps, new OAuthBearerSaslClientCallbackHandler(token));
  }

  public static class OAuthBearerSaslClientCallbackHandler implements CallbackHandler {

    private final OAuthBearerToken token;

    public OAuthBearerSaslClientCallbackHandler(Token<? extends TokenIdentifier> token) {
      this.token = new OAuthBearerToken() {
        @Override
        public String value() {
          return SaslUtil.encodeIdentifier(token.getIdentifier());
        }

        @Override
        public Set<String> scope() {
          return null;
        }

        @Override
        public long lifetimeMs() {
          return 0;
        }

        @Override
        public String principalName() {
          return null;
        }

        @Override
        public Long startTimeMs() {
          return null;
        }
      };
    }

    @Override
    public void handle(Callback[] callbacks) throws UnsupportedCallbackException {
      for (Callback callback : callbacks) {
        if (callback instanceof OAuthBearerTokenCallback)
          handleCallback((OAuthBearerTokenCallback) callback);
        else if (callback instanceof SaslExtensionsCallback)
          handleCallback((SaslExtensionsCallback) callback, Subject.getSubject(AccessController.getContext()));
        else
          throw new UnsupportedCallbackException(callback);
      }
    }

    private void handleCallback(OAuthBearerTokenCallback callback) {
      if (callback.token() != null)
        throw new IllegalArgumentException("Callback had a token already");
      callback.token(token);
    }

    /**
     * Attaches the first {@link SaslExtensions} found in the public credentials of the Subject
     */
    private static void handleCallback(SaslExtensionsCallback extensionsCallback, Subject subject) {
      if (subject != null && !subject.getPublicCredentials(SaslExtensions.class).isEmpty()) {
        SaslExtensions extensions = subject.getPublicCredentials(SaslExtensions.class).iterator().next();
        extensionsCallback.extensions(extensions);
      }
    }

  }

  @Override
  public RPCProtos.UserInformation getUserInfo(User user) {
    // Don't send user for token auth. Copied from RpcConnection.
    return null;
  }
}
