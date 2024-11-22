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
package org.apache.hadoop.hbase.coprocessor.example;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Optional;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.RpcCoprocessor;
import org.apache.hadoop.hbase.coprocessor.RpcCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RpcObserver;
import org.apache.hadoop.hbase.security.AccessDeniedException;

/**
 * Example RPC observer to verify the login id stored in client's X509 certificate's CN. Throws
 * AccessDeniedException if it doesn't match with the authenticated userName.
 */
public class X509AuthenticationObserver implements RpcCoprocessor, RpcObserver {

  @Override
  public Optional<RpcObserver> getRpcObserver() {
    return Optional.of(this);
  }

  @Override
  public void postAuthorizeConnection(ObserverContext<RpcCoprocessorEnvironment> ctx,
    String userName, X509Certificate[] clientCertificateChain) throws IOException {
    if (clientCertificateChain == null || clientCertificateChain.length == 0) {
      // No certificate provided
      return;
    }
    if (userName.endsWith("hfs.0")) {
      // Internal (Master/RS) connection - don't check
      return;
    }
    validateClientX509Cert(userName, clientCertificateChain[0]);
  }

  private void validateClientX509Cert(String userName, X509Certificate clientCert)
    throws AccessDeniedException {
    String dn = clientCert.getSubjectX500Principal().getName();
    try {
      LdapName ldapDN = new LdapName(dn);
      for (Rdn rdn : ldapDN.getRdns()) {
        if (rdn.getType().equalsIgnoreCase("CN")) {
          if (Objects.equals(userName, rdn.getValue())) {
            return;
          } else {
            throw new AccessDeniedException("Invalid client certificate userName doesn't match");
          }
        }
      }
      // Log WARN: no CN found in client's cert
    } catch (InvalidNameException e) {
      throw new RuntimeException(e);
    }
  }
}
