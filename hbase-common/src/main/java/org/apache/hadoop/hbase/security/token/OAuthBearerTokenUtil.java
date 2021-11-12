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
              return "eyJqa3UiOiJodHRwczpcL1wvY29kLTcyMTMtZ2F0ZXdheS5jb2QtNzIxMy54Y3UyLTh5OHguZGV2LmNsZHIud29ya1wvY29kLTcyMTNcL2hvbWVwYWdlXC9rbm94dG9rZW5cL2FwaVwvdjFcL2p3a3MuanNvbiIsImtpZCI6IlNlYXJuU3ZoZDlGQjhfMGVvdmhTOFh4V25LZlB0UWlyVUVmTk5Fa0NxNU0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJjc3NvX2FuZG9yIiwiYXVkIjoiY2RwLXByb3h5LXRva2VuIiwiamt1IjoiaHR0cHM6XC9cL2NvZC03MjEzLWdhdGV3YXkuY29kLTcyMTMueGN1Mi04eTh4LmRldi5jbGRyLndvcmtcL2NvZC03MjEzXC9ob21lcGFnZVwva25veHRva2VuXC9hcGlcL3YxXC9qd2tzLmpzb24iLCJraWQiOiJTZWFyblN2aGQ5RkI4XzBlb3ZoUzhYeFduS2ZQdFFpclVFZk5ORWtDcTVNIiwiaXNzIjoiS05PWFNTTyIsImV4cCI6MTYzNjc0MDQ5MSwibWFuYWdlZC50b2tlbiI6InRydWUiLCJrbm94LmlkIjoiYTZiYjllNjYtYWUwMi00ZjY4LTg1YjEtYjYzNjYzMDYxZjA0In0.Ap8GUH7IzmTHS1okk1yVh1IgifayHOI4hpb3QAylE-4OTCZ5Wbu7NDB7NHaJOaXzt4QBhmx5QHt0fndFjgKA1NSYGaoRNeHFBDxYzCG31RCApHe3rZWLJjRFQqdjvY1DEM4RRgCYxpAo18QpGWIlmM2Ms3ytO58GvlZJRsWVf8zTjfFMRB8MbYEtQReqTpB8muxXGo5lGzUp564JSw9QtjBOP8tABoEHIKIl9QbZBR0q_VDwkg8fL_tsvTfXMk7DOjnIUhIwhM2-8gDVbogmUEca2QuJQi6cAIkGB-T6eOsgttDE8aVoqpMs0FRGu97YD2k8aGvQkPSzE6j02x_0Ww";
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
