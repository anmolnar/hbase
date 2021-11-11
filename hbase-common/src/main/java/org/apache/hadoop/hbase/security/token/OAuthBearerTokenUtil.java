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
              return "eyJqa3UiOiJodHRwczpcL1wvY29kLWFna3Y3cjV3Y3R5by1nYXRld2F5MC5jb2QtNzIxMy54Y3UyLTh5OHguZGV2LmNsZHIud29ya1wvY29kLWFna3Y3cjV3Y3R5b1wvaG9tZXBhZ2VcL2tub3h0b2tlblwvYXBpXC92MVwvandrcy5qc29uIiwia2lkIjoiRlNFUzE5VzBfUVZTR1p0MHZvR1F5d3ppcDVnRHBFemRRX1Jqb2hzX0FtOCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJjc3NvX2FuZG9yIiwiYXVkIjoiY2RwLXByb3h5LXRva2VuIiwiamt1IjoiaHR0cHM6XC9cL2NvZC1hZ2t2N3I1d2N0eW8tZ2F0ZXdheTAuY29kLTcyMTMueGN1Mi04eTh4LmRldi5jbGRyLndvcmtcL2NvZC1hZ2t2N3I1d2N0eW9cL2hvbWVwYWdlXC9rbm94dG9rZW5cL2FwaVwvdjFcL2p3a3MuanNvbiIsImtpZCI6IkZTRVMxOVcwX1FWU0dadDB2b0dReXd6aXA1Z0RwRXpkUV9Sam9oc19BbTgiLCJpc3MiOiJLTk9YU1NPIiwiZXhwIjoxNjM2NjQ0MDI5LCJtYW5hZ2VkLnRva2VuIjoidHJ1ZSIsImtub3guaWQiOiJjZGRmZTI3NS04MTdlLTRhOWUtYTk0NC01MmFmOTE2ZmU2NTgifQ.tR5jWBEvK_WAPYx0ipNKpJ1T-e5ir_jzP-CktHeLo5RoEhostBBN1a4Y7wB2SjMUAQ5EnxE8BVhDttfmAxkSObU7CHoLFxScsDEBkCelrt2KUkbpBHvzpgmm2k7NpO4Fyz__HuR3CJ3iJtjrsj2fEMNyRM_ipAsW22tAl3o2lrs3ABxD9px37sTZDW5MIDiWRgcOvzFWYSDOqT6ZEa7fomDhBFitgUmNnF9duzc8mMBSxcycXU8eXp6bTLXkPJqRes7M7DLCyQwvoWPicEbFIuRRdtV90Oq0EGe3o5U2B28LPXUlsBYWZWS2n9Et7Iq0EhargBesAaaZWTt0Bd8WHw";
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
