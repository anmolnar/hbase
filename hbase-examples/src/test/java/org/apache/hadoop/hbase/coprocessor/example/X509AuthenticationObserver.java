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

import org.apache.hadoop.hbase.coprocessor.MasterCoprocessor;
import org.apache.hadoop.hbase.coprocessor.MasterCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.MasterObserver;
import org.apache.hadoop.hbase.coprocessor.ObserverContext;
import org.apache.hadoop.hbase.coprocessor.RegionServerCoprocessor;
import org.apache.hadoop.hbase.coprocessor.RegionServerCoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.RegionServerObserver;
import org.apache.hadoop.hbase.security.AccessDeniedException;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Optional;

/**
 * Example Master/RS observer to verify the login id stored in client's X509 certificate's CN.
 * Throws AccessDeniedException if it doesn't match with the authenticated userName.
 */
public class X509AuthenticationObserver implements RegionServerCoprocessor, RegionServerObserver,
  MasterCoprocessor, MasterObserver {

  @Override public Optional<MasterObserver> getMasterObserver() {
    return Optional.of(this);
  }

  @Override public Optional<RegionServerObserver> getRegionServerObserver() {
    return Optional.of(this);
  }

  @Override
  public void postAuthorizeMasterConnection(ObserverContext<MasterCoprocessorEnvironment> ctx,
    String userName, X509Certificate[] clientCertificateChain) throws AccessDeniedException {
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

  @Override public void postAuthorizeRegionServerConnection(
    ObserverContext<RegionServerCoprocessorEnvironment> ctx, String userName,
    X509Certificate[] clientCertificateChain) throws AccessDeniedException {
    if (clientCertificateChain == null || clientCertificateChain.length == 0) {
      return;
    }
    validateClientX509Cert(userName, clientCertificateChain[0]);
  }

  private void validateClientX509Cert(String userName, X509Certificate clientCert)
    throws AccessDeniedException {
    String dn = clientCert.getSubjectX500Principal().getName();
    try {
      LdapName ldapDN = new LdapName(dn);
      for (Rdn rdn: ldapDN.getRdns()) {
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
