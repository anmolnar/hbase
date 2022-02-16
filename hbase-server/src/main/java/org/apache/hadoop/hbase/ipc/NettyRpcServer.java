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
package org.apache.hadoop.hbase.ipc;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseInterfaceAudience;
import org.apache.hadoop.hbase.HBaseServerBase;
import org.apache.hadoop.hbase.Server;
import org.apache.hadoop.hbase.io.crypto.tls.SSLContextAndOptions;
import org.apache.hadoop.hbase.io.crypto.tls.X509Util;
import org.apache.hadoop.hbase.regionserver.HRegionServer;
import org.apache.hadoop.hbase.security.HBasePolicyProvider;
import org.apache.hadoop.hbase.util.NettyEventLoopGroupConfig;
import org.apache.hadoop.security.authorize.ServiceAuthorizationManager;
import org.apache.yetus.audience.InterfaceAudience;
import org.apache.zookeeper.common.X509Exception;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.hbase.thirdparty.io.netty.bootstrap.ServerBootstrap;
import org.apache.hbase.thirdparty.io.netty.buffer.ByteBuf;
import org.apache.hbase.thirdparty.io.netty.channel.Channel;
import org.apache.hbase.thirdparty.io.netty.channel.ChannelHandler;
import org.apache.hbase.thirdparty.io.netty.channel.ChannelHandlerContext;
import org.apache.hbase.thirdparty.io.netty.channel.ChannelInitializer;
import org.apache.hbase.thirdparty.io.netty.channel.ChannelOption;
import org.apache.hbase.thirdparty.io.netty.channel.ChannelPipeline;
import org.apache.hbase.thirdparty.io.netty.channel.EventLoopGroup;
import org.apache.hbase.thirdparty.io.netty.channel.ServerChannel;
import org.apache.hbase.thirdparty.io.netty.channel.group.ChannelGroup;
import org.apache.hbase.thirdparty.io.netty.channel.group.DefaultChannelGroup;
import org.apache.hbase.thirdparty.io.netty.channel.nio.NioEventLoopGroup;
import org.apache.hbase.thirdparty.io.netty.channel.socket.nio.NioServerSocketChannel;
import org.apache.hbase.thirdparty.io.netty.handler.codec.FixedLengthFrameDecoder;
import org.apache.hbase.thirdparty.io.netty.handler.ssl.OptionalSslHandler;
import org.apache.hbase.thirdparty.io.netty.handler.ssl.SslContext;
import org.apache.hbase.thirdparty.io.netty.handler.ssl.SslHandler;
import org.apache.hbase.thirdparty.io.netty.util.concurrent.DefaultThreadFactory;
import org.apache.hbase.thirdparty.io.netty.util.concurrent.GlobalEventExecutor;

/**
 * An RPC server with Netty4 implementation.
 * @since 2.0.0
 */
@InterfaceAudience.LimitedPrivate({HBaseInterfaceAudience.CONFIG})
public class NettyRpcServer extends RpcServer {
  public static final Logger LOG = LoggerFactory.getLogger(NettyRpcServer.class);

  /**
   * Name of property to change netty rpc server eventloop thread count. Default is 0.
   * Tests may set this down from unlimited.
   */
  public static final String HBASE_NETTY_EVENTLOOP_RPCSERVER_THREADCOUNT_KEY =
    "hbase.netty.eventloop.rpcserver.thread.count";
  private static final int EVENTLOOP_THREADCOUNT_DEFAULT = 0;
  private static final String HBASE_NETTY_RPCSERVER_TLS_ENABLED =
    "hbase.netty.rpcserver.tls.enabled";

  /**
   * The first byte in TLS protocol is the content type of the subsequent record.
   * Handshakes use value 22 (0x16) so the first byte offered on any TCP connection
   * attempting to establish a TLS connection will be this value.
   * https://tools.ietf.org/html/rfc8446#page-79
   */
  private static final byte TLS_HANDSHAKE_RECORD_TYPE = 0x16;

  private final InetSocketAddress bindAddress;

  private final CountDownLatch closed = new CountDownLatch(1);
  private final Channel serverChannel;
  private final ChannelGroup allChannels =
    new DefaultChannelGroup(GlobalEventExecutor.INSTANCE, true);

  private final X509Util x509Util;

  public NettyRpcServer(Server server, String name, List<BlockingServiceAndInterface> services,
      InetSocketAddress bindAddress, Configuration conf, RpcScheduler scheduler,
      boolean reservoirEnabled) throws IOException {
    super(server, name, services, bindAddress, conf, scheduler, reservoirEnabled);
    this.x509Util = new X509Util(conf);
    this.bindAddress = bindAddress;
    EventLoopGroup eventLoopGroup;
    Class<? extends ServerChannel> channelClass;
    if (server instanceof HRegionServer) {
      NettyEventLoopGroupConfig config = ((HBaseServerBase) server).getEventLoopGroupConfig();
      eventLoopGroup = config.group();
      channelClass = config.serverChannelClass();
    } else {
      int threadCount = server == null? EVENTLOOP_THREADCOUNT_DEFAULT:
        server.getConfiguration().getInt(HBASE_NETTY_EVENTLOOP_RPCSERVER_THREADCOUNT_KEY,
          EVENTLOOP_THREADCOUNT_DEFAULT);
      eventLoopGroup = new NioEventLoopGroup(threadCount,
        new DefaultThreadFactory("NettyRpcServer", true, Thread.MAX_PRIORITY));
      channelClass = NioServerSocketChannel.class;
    }
    ServerBootstrap bootstrap = new ServerBootstrap().group(eventLoopGroup).channel(channelClass)
        .childOption(ChannelOption.TCP_NODELAY, tcpNoDelay)
        .childOption(ChannelOption.SO_KEEPALIVE, tcpKeepAlive)
        .childOption(ChannelOption.SO_REUSEADDR, true)
        .childHandler(new ChannelInitializer<Channel>() {

          @Override
          protected void initChannel(Channel ch) throws Exception {
            ChannelPipeline pipeline = ch.pipeline();
            FixedLengthFrameDecoder preambleDecoder = new FixedLengthFrameDecoder(6);
            preambleDecoder.setSingleDecode(true);
            if (conf.getBoolean(HBASE_NETTY_RPCSERVER_TLS_ENABLED, false)) {
              initSSL(pipeline, true);
            }
            pipeline.addLast("preambleDecoder", preambleDecoder);
            pipeline.addLast("preambleHandler", createNettyRpcServerPreambleHandler());
            pipeline.addLast("frameDecoder", new NettyRpcFrameDecoder(maxRequestSize));
            pipeline.addLast("decoder", new NettyRpcServerRequestDecoder(allChannels, metrics));
            pipeline.addLast("encoder", new NettyRpcServerResponseEncoder(metrics));
          }
        });
    try {
      serverChannel = bootstrap.bind(this.bindAddress).sync().channel();
      LOG.info("Bind to {}", serverChannel.localAddress());
    } catch (InterruptedException e) {
      throw new InterruptedIOException(e.getMessage());
    }
    initReconfigurable(conf);
    this.scheduler.init(new RpcSchedulerContext(this));
  }

  @InterfaceAudience.Private
  protected NettyRpcServerPreambleHandler createNettyRpcServerPreambleHandler() {
    return new NettyRpcServerPreambleHandler(NettyRpcServer.this);
  }

  @Override
  public synchronized void start() {
    if (started) {
      return;
    }
    authTokenSecretMgr = createSecretManager();
    if (authTokenSecretMgr != null) {
      // Start AuthenticationTokenSecretManager in synchronized way to avoid race conditions in
      // LeaderElector start. See HBASE-25875
      synchronized (authTokenSecretMgr) {
        setSecretManager(authTokenSecretMgr);
        authTokenSecretMgr.start();
      }
    }
    this.authManager = new ServiceAuthorizationManager();
    HBasePolicyProvider.init(conf, authManager);
    scheduler.start();
    started = true;
  }

  @Override
  public synchronized void stop() {
    if (!running) {
      return;
    }
    LOG.info("Stopping server on " + this.serverChannel.localAddress());
    if (authTokenSecretMgr != null) {
      authTokenSecretMgr.stop();
      authTokenSecretMgr = null;
    }
    allChannels.close().awaitUninterruptibly();
    serverChannel.close();
    scheduler.stop();
    closed.countDown();
    running = false;
  }

  @Override
  public synchronized void join() throws InterruptedException {
    closed.await();
  }

  @Override
  public synchronized InetSocketAddress getListenerAddress() {
    return ((InetSocketAddress) serverChannel.localAddress());
  }

  @Override
  public void setSocketSendBufSize(int size) {
  }

  @Override
  public int getNumOpenConnections() {
    int channelsCount = allChannels.size();
    // allChannels also contains the server channel, so exclude that from the count.
    return channelsCount > 0 ? channelsCount - 1 : channelsCount;
  }

  private synchronized void initSSL(ChannelPipeline p, boolean supportPlaintext) throws
    X509Exception {
    SslContext nettySslContext;

    SSLContextAndOptions sslContextAndOptions = x509Util.getDefaultSSLContextAndOptions();
    nettySslContext = sslContextAndOptions
      .createNettyJdkSslContext(sslContextAndOptions.getSSLContext(), false);

    if (supportPlaintext) {
      p.addLast("ssl", new NettyRpcServer.DualModeSslHandler(nettySslContext));
      LOG.debug("Dual mode SSL handler added for channel: {}", p.channel());
    } else {
      p.addLast("ssl", nettySslContext.newHandler(p.channel().alloc()));
      LOG.debug("SSL handler added for channel: {}", p.channel());
    }
  }

  /**
   * A handler that detects whether the client would like to use
   * TLS or not and responds in kind. The first bytes are examined
   * for the static TLS headers to make the determination and
   * placed back in the stream with the correct ChannelHandler
   * instantiated.
   */
  class DualModeSslHandler extends OptionalSslHandler {

    DualModeSslHandler(SslContext sslContext) {
      super(sslContext);
    }

    @Override
    protected void decode(ChannelHandlerContext context, ByteBuf in, List<Object> out)
      throws Exception {
      if (in.readableBytes() >= 5) {
        super.decode(context, in, out);
      } else if (in.readableBytes() > 0) {
        // It requires 5 bytes to detect a proper ssl connection. In the
        // case that the server receives fewer, check if we can fail to plaintext.
        // This will occur when for any four letter work commands.
        if (TLS_HANDSHAKE_RECORD_TYPE != in.getByte(0)) {
          LOG.debug("first byte {} does not match TLS handshake, failing to plaintext",
            in.getByte(0));
          handleNonSsl(context);
        }
      }
    }

    /**
     * pulled directly from OptionalSslHandler to allow for access
     * @param context
     */
    private void handleNonSsl(ChannelHandlerContext context) {
      ChannelHandler handler = this.newNonSslHandler(context);
      if (handler != null) {
        context.pipeline().replace(this, this.newNonSslHandlerName(), handler);
      } else {
        context.pipeline().remove(this);
      }
    }

    @Override
    protected SslHandler newSslHandler(ChannelHandlerContext context, SslContext sslContext) {
      LOG.debug("creating ssl handler for context {}", context);
      return super.newSslHandler(context, sslContext);
    }

    @Override
    protected ChannelHandler newNonSslHandler(ChannelHandlerContext context) {
      LOG.debug("creating plaintext handler for context {}", context);
      // Mark handshake finished if it's a insecure cnxn
      allChannels.add(context.channel());
      return super.newNonSslHandler(context);
    }

  }

}
