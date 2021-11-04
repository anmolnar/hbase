/**
 *
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
package org.apache.hadoop.hbase.security.token;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Set;
import javax.security.auth.Subject;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.oauthbearer.OAuthBearerToken;
import org.apache.hadoop.hbase.security.oauthbearer.internals.OAuthBearerSaslClientProvider;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.security.token.Token;
import org.apache.yetus.audience.InterfaceAudience;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility methods for obtaining OAuthBearer / JWT authentication tokens.
 */
@InterfaceAudience.Public
public final class OAuthBearerTokenUtil {
  private static final Logger LOG = LoggerFactory.getLogger(OAuthBearerTokenUtil.class);

  static {
    OAuthBearerSaslClientProvider.initialize(); // not part of public API
    LOG.info("OAuthBearer SASL client provider has been initialized");
  }

  private OAuthBearerTokenUtil() {  }

  public static void addTokenForUser(Configuration conf, User user) {
    try {
      user.addToken(new Token<>(null, null, new Text("JWT_AUTH_TOKEN"), null));
      user.runAs(new PrivilegedAction<Object>() {
        @Override public Object run() {
          Subject subject = Subject.getSubject(AccessController.getContext());
          OAuthBearerToken jwt = new OAuthBearerToken() {
            @Override public String value() {
              return "eyJqa3UiOiJodHRwczpcL1wvY29kLTcyMTItZ2F0ZXdheS5jb2QtNzIxMi54Y3UyLTh5OHguZGV2LmNsZHIud29ya1wvY29kLTcyMTJcL2hvbWVwYWdlXC9rbm94dG9rZW5cL2FwaVwvdjFcL2p3a3MuanNvbiIsImtpZCI6IkpSd2VXVHdzRzRfZ09GeUhxTm1idEo3RzE3Yll4OG43V2hfYU9oa0NRSWMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjc3NvX2FuZG9yIiwiYXVkIjoiY2RwLXByb3h5LXRva2VuIiwiamt1IjoiaHR0cHM6XC9cL2NvZC03MjEyLWdhdGV3YXkuY29kLTcyMTIueGN1Mi04eTh4LmRldi5jbGRyLndvcmtcL2NvZC03MjEyXC9ob21lcGFnZVwva25veHRva2VuXC9hcGlcL3YxXC9qd2tzLmpzb24iLCJraWQiOiJKUndlV1R3c0c0X2dPRnlIcU5tYnRKN0cxN2JZeDhuN1doX2FPaGtDUUljIiwiaXNzIjoiS05PWFNTTyIsImV4cCI6MTYzNjAzNjM0MywibWFuYWdlZC50b2tlbiI6InRydWUiLCJrbm94LmlkIjoiMTc3MzNhNzYtNTg5YS00ZDZkLThkY2YtYTAzNmM2ZDEzY2Q0In0.VjNL1sTvrBzRlq44XTjs4yqD__nQGNBWtTxZbqfyIoCa-sFLOjcVrzI7HIv2r67hE6VbAVn-bF2S4yo6tYCw9HQP1XKrMy_XHv3GJrN9562JzNzEgzU5ZOzc5xtUTpX76HOHkrzZsYgx2zErhx7T7WfQZIjbwAIRtjfHYa25DcsWYx70YRSytmQxGX0REmShRUctRrJVx0A_-3GA_93BVfEDvbO9MjHvVsI22Oiu1h0ZS0gH2Qt6ceYf1imZ0psu7lc8ldco7aSMB3HPyn8nstJRwvquCAWO4HAVTM2PgXvs5ExaZ5PgJCZ9K6msNM6OQPi-sClMiMX90R9TVRdRvQ";
            }

            @Override public Set<String> scope() {
              return null;
            }

            @Override public long lifetimeMs() {
              return 0;
            }

            @Override public String principalName() {
              return "csso_andor";
            }

            @Override public Long startTimeMs() {
              return null;
            }
          };
          subject.getPrivateCredentials().add(jwt);
          return null;
        }
      });
    } catch (Exception e) {
      LOG.error("JWT token error", e);
    }
  }
}
