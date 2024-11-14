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

import java.io.File;
import java.security.Security;
import org.apache.commons.io.FileUtils;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseClassTestRule;
import org.apache.hadoop.hbase.HBaseTestingUtil;
import org.apache.hadoop.hbase.client.Connection;
import org.apache.hadoop.hbase.coprocessor.CoprocessorHost;
import org.apache.hadoop.hbase.io.crypto.tls.KeyStoreFileType;
import org.apache.hadoop.hbase.io.crypto.tls.X509KeyType;
import org.apache.hadoop.hbase.io.crypto.tls.X509TestContext;
import org.apache.hadoop.hbase.io.crypto.tls.X509Util;
import org.apache.hadoop.hbase.ipc.TestNettyTlsIPC;
import org.apache.hadoop.hbase.testclassification.MediumTests;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.experimental.categories.Category;

@Category(MediumTests.class)
public class X509AuthenticationExample {
  @ClassRule
  public static final HBaseClassTestRule CLASS_RULE =
    HBaseClassTestRule.forClass(X509AuthenticationExample.class);

  private static final HBaseTestingUtil UTIL = new HBaseTestingUtil();
  private static final Configuration CONF = UTIL.getConfiguration();

  private X509TestContext x509TestContext;
  private File tempDir;

  @BeforeClass
  public static void setUpBeforeClass() {
    Security.addProvider(new BouncyCastleProvider());

    // Force TLS on server side
    CONF.setBoolean(X509Util.HBASE_SERVER_NETTY_TLS_ENABLED, true);
    CONF.setBoolean(X509Util.HBASE_SERVER_NETTY_TLS_SUPPORTPLAINTEXT, false);

    // We're testing, so don't bother with hostname checks
    CONF.setBoolean(X509Util.HBASE_SERVER_NETTY_TLS_VERIFY_CLIENT_HOSTNAME, false);
    CONF.setBoolean(X509Util.HBASE_CLIENT_NETTY_TLS_VERIFY_SERVER_HOSTNAME, false);

    // Force client mTLS
    CONF.setStrings(X509Util.HBASE_SERVER_NETTY_TLS_CLIENT_AUTH_MODE, "NEED");

    // Enable TLS on client side
    CONF.setBoolean(X509Util.HBASE_CLIENT_NETTY_TLS_ENABLED, true);

    // Setup co-processors
    CONF.setStrings(CoprocessorHost.RPC_COPROCESSOR_CONF_KEY,
      X509AuthenticationObserver.class.getName());
  }

  @Before
  public void setUp() throws Exception {
    tempDir = new File(UTIL.getDataTestDir(TestNettyTlsIPC.class.getSimpleName()).toString())
      .getCanonicalFile();
    FileUtils.forceMkdir(tempDir);

    x509TestContext = X509TestContext.newBuilder(CONF).setTempDir(tempDir)
      .setKeyStoreKeyType(X509KeyType.RSA).setKeyStorePassword("Pa$$w0rd".toCharArray())
      .setTrustStoreKeyType(X509KeyType.RSA).setTrustStorePassword("Pa$$w0rd".toCharArray())
      .setKeyStoreCN(System.getProperty("user.name")).build();
    x509TestContext.setConfigurations(KeyStoreFileType.JKS, KeyStoreFileType.JKS);

    UTIL.startMiniCluster();
  }

  @After
  public void tearDown() throws Exception {
    UTIL.shutdownMiniCluster();
    if (x509TestContext != null) {
      x509TestContext.clearConfigurations();
    }
    if (tempDir != null) {
      tempDir.delete();
    }
  }

  @Test
  public void testPostAuthorization() throws Exception {
    Connection connection = UTIL.getConnection();
    connection.getClusterId();
    connection.close();
  }

}
