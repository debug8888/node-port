const express = require('express');
const net = require('net');
const fs = require('fs');
const path = require('path');
const bodyParser = require('body-parser');
const { SocksProxyAgent } = require('socks-proxy-agent');
const http = require('http');
const https = require('https');
const find = require('find-process');
const { exec } = require('child_process');
const app = express();
const PORT = 3000;

// Data storage
const CONFIG_FILE = path.join(__dirname, 'config.json');
let forwardingRules = [];
let activeTcpServers = {};
let activeSocketServers = {};
let systemPorts = [];

// 判断是否为Unix socket路径
function isUnixSocketPath(path) {
  return path && (path.startsWith('/') || path.includes('/'));
}

// 判断是否为Windows命名管道
function isWindowsNamedPipe(path) {
  return path && (path.startsWith('\\\\.\\pipe\\') || path.startsWith('\\\\?\\pipe\\'));
}

// 判断是否为socket类型地址
function isSocketAddress(address) {
  return isUnixSocketPath(address) || isWindowsNamedPipe(address);
}

// 格式化Windows命名管道路径
function formatWindowsNamedPipe(pipeName) {
  if (!pipeName.startsWith('\\\\.\\pipe\\') && !pipeName.startsWith('\\\\?\\pipe\\')) {
    return '\\\\.\\pipe\\' + pipeName;
  }
  return pipeName;
}

// 获取系统上已使用的端口
async function getSystemPorts() {
  return new Promise((resolve, reject) => {
    // 在Windows上使用netstat命令获取端口信息
    if (process.platform === 'win32') {
      exec('netstat -ano', (error, stdout, stderr) => {
        if (error) {
          console.error(`Error executing netstat: ${error}`);
          return resolve([]);
        }
        
        // 解析netstat输出获取端口信息
        const lines = stdout.split('\n');
        const portMap = new Map();
        
        for (const line of lines) {
          // TCP和UDP行
          const tcpMatch = line.match(/\s+(TCP|UDP)\s+(\S+):(\d+)\s+\S+\s+(\S+)\s+(\d+)?/i);
          if (tcpMatch) {
            const [, protocol, ip, port, state, pid] = tcpMatch;
            // 仅保留LISTENING状态的端口
            if (state.trim() === 'LISTENING' || protocol === 'UDP') {
              if (!portMap.has(port)) {
                portMap.set(port, {
                  port: parseInt(port),
                  protocol,
                  pid: pid ? parseInt(pid) : null,
                  state: state.trim(),
                  processName: 'Unknown'
                });
              }
            }
          }
        }
        
        // 将Map转换为数组并查找进程名称
        const portsArray = Array.from(portMap.values());
        
        // 使用find-process查找进程名称
        const promises = portsArray.map(async (portInfo) => {
          if (portInfo.pid) {
            try {
              const processes = await find('pid', portInfo.pid);
              if (processes && processes.length > 0) {
                portInfo.processName = processes[0].name;
              }
            } catch (err) {
              console.error(`Error finding process for PID ${portInfo.pid}: ${err}`);
            }
          }
          return portInfo;
        });
        
        Promise.all(promises)
          .then(results => {
            // 排序端口信息
            systemPorts = results.sort((a, b) => a.port - b.port);
            resolve(systemPorts);
          })
          .catch(err => {
            console.error('Error processing port information:', err);
            resolve([]);
          });
      });
    } else {
      // 在Unix/Linux/macOS上使用lsof命令
      exec('lsof -i -P -n | grep LISTEN', (error, stdout, stderr) => {
        if (error) {
          console.error(`Error executing lsof: ${error}`);
          return resolve([]);
        }
        
        const lines = stdout.split('\n');
        const portMap = new Map();
        
        for (const line of lines) {
          if (!line.trim()) continue;
          
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 9) {
            const processName = parts[0];
            const pid = parseInt(parts[1]);
            const addressInfo = parts[8];
            
            const portMatch = addressInfo.match(/:(\d+)$/);
            if (portMatch) {
              const port = parseInt(portMatch[1]);
              if (!portMap.has(port)) {
                portMap.set(port, {
                  port,
                  protocol: 'TCP',
                  pid,
                  state: 'LISTENING',
                  processName
                });
              }
            }
          }
        }
        
        systemPorts = Array.from(portMap.values()).sort((a, b) => a.port - b.port);
        resolve(systemPorts);
      });
    }
  });
}

// 每60秒更新一次系统端口信息
function startPortMonitoring() {
  // 立即更新一次
  getSystemPorts().catch(err => console.error('Error updating system ports:', err));
  
  // 设置定时更新
  setInterval(() => {
    getSystemPorts().catch(err => console.error('Error updating system ports:', err));
  }, 60000); // 每60秒更新一次
}

// Load existing configuration
function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const data = fs.readFileSync(CONFIG_FILE, 'utf8');
      forwardingRules = JSON.parse(data);
      console.log('Configuration loaded:', forwardingRules);
    }
  } catch (err) {
    console.error('Error loading configuration:', err);
  }
}

// Save configuration
function saveConfig() {
  try {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(forwardingRules, null, 2), 'utf8');
    console.log('Configuration saved');
  } catch (err) {
    console.error('Error saving configuration:', err);
  }
}

// Start socket server for forwarding
function startSocketForwarding(rule) {
  const { id, sourceAddress, targetAddress, forwardingType } = rule;
  
  // Stop existing server if it exists
  if (activeSocketServers[id]) {
    activeSocketServers[id].close();
    delete activeSocketServers[id];
  }
  
  // 确保Unix socket文件不存在
  if (isUnixSocketPath(sourceAddress) && fs.existsSync(sourceAddress)) {
    try {
      fs.unlinkSync(sourceAddress);
    } catch (err) {
      console.error(`Error removing existing socket file ${sourceAddress}:`, err);
      rule.status = 'error';
      rule.error = `Cannot remove existing socket file: ${err.message}`;
      saveConfig();
      return null;
    }
  }
  
  const server = net.createServer((socket) => {
    if (forwardingType === 'socks') {
      // SOCKS代理转发
      handleSocksForwarding(socket, rule);
    } else if (forwardingType === 'http') {
      // HTTP代理转发
      handleHttpForwarding(socket, rule);
    } else {
      // 普通TCP/Socket转发
      const client = new net.Socket();
      
      const connectTarget = () => {
        if (isSocketAddress(targetAddress)) {
          // 连接到socket
          client.connect(targetAddress, () => {
            socket.pipe(client);
            client.pipe(socket);
          });
        } else {
          // 假设是 host:port 格式
          const [host, port] = targetAddress.split(':');
          client.connect(parseInt(port), host, () => {
            socket.pipe(client);
            client.pipe(socket);
          });
        }
      };
      
      connectTarget();
      
      client.on('error', (err) => {
        console.error(`Connection error to ${targetAddress}:`, err);
        socket.end();
      });
      
      socket.on('error', (err) => {
        console.error(`Client socket error:`, err);
        client.end();
      });
    }
  });
  
  server.on('error', (err) => {
    console.error(`Error starting socket server on ${sourceAddress}:`, err);
    rule.status = 'error';
    rule.error = err.message;
    saveConfig();
  });
  
  // 根据地址类型监听
  if (isSocketAddress(sourceAddress)) {
    // 为socket服务器设置权限
    server.listen(sourceAddress, () => {
      console.log(`Forwarding from socket ${sourceAddress} to ${targetAddress} (${forwardingType})`);
      if (isUnixSocketPath(sourceAddress)) {
        try {
          fs.chmodSync(sourceAddress, '0777');
        } catch (err) {
          console.warn(`Warning: Could not set permissions on socket file: ${err.message}`);
        }
      }
      rule.status = 'active';
      rule.error = '';
      saveConfig();
    });
  } else {
    // 处理为IP:Port格式
    const [host, port] = sourceAddress.split(':');
    const bindIP = host || '0.0.0.0';
    
    server.listen(parseInt(port), bindIP, () => {
      console.log(`Forwarding from ${bindIP}:${port} to ${targetAddress} (${forwardingType || 'tcp'})`);
      rule.status = 'active';
      rule.error = '';
      saveConfig();
    });
  }
  
  activeSocketServers[id] = server;
  return server;
}

// 处理SOCKS代理转发
function handleSocksForwarding(socket, rule) {
  const targetParts = rule.targetAddress.split(':');
  const targetHost = targetParts[0] || '127.0.0.1';
  const targetPort = parseInt(targetParts[1]);

  // 创建一个简单的协议处理，这里仅作为一个示例
  // 注意：这是一个简化的实现，完整的SOCKS协议实现需要更复杂的代码
  let buffer = Buffer.alloc(0);
  
  socket.on('data', (data) => {
    buffer = Buffer.concat([buffer, data]);
    
    try {
      // 尝试使用SOCKS代理
      const agent = new SocksProxyAgent(`socks://${targetHost}:${targetPort}`);
      
      // 我们需要从原始请求中提取目标信息
      // 这个实现是简化的，实际SOCKS客户端会发送特定格式的请求
      socket.removeAllListeners('data');
      
      // 使用代理转发后续请求
      const reqOptions = {
        hostname: 'example.com', // 假设的目标网站
        port: 80,
        path: '/',
        method: 'GET',
        agent: agent
      };
      
      const req = http.request(reqOptions, (res) => {
        // 将响应传回客户端
        res.pipe(socket);
      });
      
      // 将收到的数据转发到目标
      req.write(buffer);
      socket.pipe(req);
      
      req.on('error', (err) => {
        console.error('Proxy request error:', err);
        socket.end();
      });
    } catch (err) {
      console.error('Error setting up SOCKS proxy:', err);
      socket.end();
    }
  });
  
  socket.on('error', (err) => {
    console.error('SOCKS client socket error:', err);
  });
}

// 处理HTTP代理转发
function handleHttpForwarding(socket, rule) {
  const targetParts = rule.targetAddress.split(':');
  const targetHost = targetParts[0] || '127.0.0.1';
  const targetPort = parseInt(targetParts[1]);
  
  let buffer = Buffer.alloc(0);
  let headerEnd = false;
  
  socket.on('data', (data) => {
    if (headerEnd) {
      // 请求头已经处理过，直接转发数据
      proxyRequest.write(data);
      return;
    }
    
    buffer = Buffer.concat([buffer, data]);
    const bufferString = buffer.toString();
    
    // 寻找HTTP请求头结束标记
    if (bufferString.includes('\r\n\r\n')) {
      headerEnd = true;
      
      // 解析HTTP请求
      const headerLines = bufferString.split('\r\n');
      const requestLine = headerLines[0].split(' ');
      const method = requestLine[0];
      let path = requestLine[1];
      let host = '';
      
      // 从请求头中提取Host
      for (const line of headerLines) {
        if (line.toLowerCase().startsWith('host:')) {
          host = line.substring(5).trim();
          break;
        }
      }
      
      // 如果是CONNECT方法（HTTPS隧道）
      if (method === 'CONNECT') {
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        
        // 创建到目标的直接连接
        const client = net.connect(targetPort, targetHost, () => {
          socket.pipe(client);
          client.pipe(socket);
        });
        
        client.on('error', (err) => {
          console.error('HTTPS tunnel error:', err);
          socket.end();
        });
        
        return;
      }
      
      // 一般HTTP请求
      const options = {
        hostname: targetHost,
        port: targetPort,
        path: path,
        method: method,
        headers: {}
      };
      
      // 复制请求头
      for (let i = 1; i < headerLines.length; i++) {
        const line = headerLines[i];
        if (!line || line === '\r\n') break;
        
        const colonIndex = line.indexOf(':');
        if (colonIndex !== -1) {
          const headerName = line.substring(0, colonIndex).trim();
          const headerValue = line.substring(colonIndex + 1).trim();
          options.headers[headerName] = headerValue;
        }
      }
      
      const proxyRequest = http.request(options, (proxyResponse) => {
        socket.write(`HTTP/${proxyResponse.httpVersion} ${proxyResponse.statusCode} ${proxyResponse.statusMessage}\r\n`);
        
        Object.keys(proxyResponse.headers).forEach(key => {
          socket.write(`${key}: ${proxyResponse.headers[key]}\r\n`);
        });
        
        socket.write('\r\n');
        proxyResponse.pipe(socket);
      });
      
      // 提取并发送请求主体
      const bodyStartPos = bufferString.indexOf('\r\n\r\n') + 4;
      if (bodyStartPos < buffer.length) {
        const bodyData = buffer.slice(bodyStartPos);
        proxyRequest.write(bodyData);
      }
      
      socket.pipe(proxyRequest);
      
      proxyRequest.on('error', (err) => {
        console.error('HTTP proxy error:', err);
        socket.end();
      });
    }
  });
  
  socket.on('error', (err) => {
    console.error('HTTP client socket error:', err);
  });
}

// Start TCP server for port forwarding (保留向后兼容性)
function startPortForwarding(rule) {
  const { id, sourceIP, sourcePort, targetHost, targetPort } = rule;
  
  // Convert to new format and call the new function
  const sourceAddress = sourceIP ? `${sourceIP}:${sourcePort}` : `0.0.0.0:${sourcePort}`;
  const targetAddress = `${targetHost}:${targetPort}`;
  
  rule.sourceAddress = sourceAddress;
  rule.targetAddress = targetAddress;
  
  return startSocketForwarding(rule);
}

// Stop all forwarding
function stopAllForwarding() {
  // Stop TCP servers
  Object.values(activeTcpServers).forEach(server => {
    try {
      server.close();
    } catch (err) {
      console.error('Error stopping TCP server:', err);
    }
  });
  activeTcpServers = {};
  
  // Stop socket servers
  Object.values(activeSocketServers).forEach(server => {
    try {
      server.close();
    } catch (err) {
      console.error('Error stopping socket server:', err);
    }
  });
  activeSocketServers = {};
}

// Stop specific forwarding
function stopForwarding(id) {
  if (activeTcpServers[id]) {
    activeTcpServers[id].close();
    delete activeTcpServers[id];
    
    const rule = forwardingRules.find(r => r.id === id);
    if (rule) {
      rule.status = 'stopped';
      saveConfig();
    }
    return true;
  }
  
  if (activeSocketServers[id]) {
    activeSocketServers[id].close();
    delete activeSocketServers[id];
    
    const rule = forwardingRules.find(r => r.id === id);
    if (rule) {
      rule.status = 'stopped';
      
      // 删除Unix socket文件
      if (rule.sourceAddress && isUnixSocketPath(rule.sourceAddress) && fs.existsSync(rule.sourceAddress)) {
        try {
          fs.unlinkSync(rule.sourceAddress);
        } catch (err) {
          console.error(`Error removing socket file ${rule.sourceAddress}:`, err);
        }
      }
      
      saveConfig();
    }
    return true;
  }
  
  return false;
}

// Start all forwarding rules
function startAllForwarding() {
  forwardingRules.forEach(rule => {
    if (rule.active) {
      // 处理旧格式的规则
      if (!rule.sourceAddress && rule.sourcePort) {
        rule.sourceAddress = rule.sourceIP ? `${rule.sourceIP}:${rule.sourcePort}` : `0.0.0.0:${rule.sourcePort}`;
        rule.targetAddress = `${rule.targetHost}:${rule.targetPort}`;
      }
      
      startSocketForwarding(rule);
    } else {
      rule.status = 'inactive';
    }
  });
}

// Configure middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Routes
app.get('/', (req, res) => {
  res.render('index', { rules: forwardingRules, systemPorts });
});

// 添加获取系统端口的API
app.get('/api/system-ports', async (req, res) => {
  try {
    const ports = await getSystemPorts();
    res.json(ports);
  } catch (err) {
    console.error('Error getting system ports:', err);
    res.status(500).json({ error: 'Failed to get system ports' });
  }
});

// 刷新系统端口信息
app.post('/refresh-ports', async (req, res) => {
  try {
    await getSystemPorts();
    res.redirect('/');
  } catch (err) {
    console.error('Error refreshing system ports:', err);
    res.status(500).send('Failed to refresh system ports');
  }
});

app.post('/add', (req, res) => {
  const { sourceAddress, targetAddress, forwardingType } = req.body;
  
  // 向后兼容的参数处理
  if (req.body.sourcePort) {
    const sourceIP = req.body.sourceIP || '';
    const sourcePort = req.body.sourcePort;
    const targetHost = req.body.targetHost;
    const targetPort = req.body.targetPort;
    
    if (!sourcePort || !targetHost || !targetPort) {
      return res.status(400).json({ 
        success: false, 
        message: 'Source port, target host and target port are required' 
      });
    }
    
    // 生成地址格式
    req.body.sourceAddress = sourceIP ? `${sourceIP}:${sourcePort}` : `0.0.0.0:${sourcePort}`;
    req.body.targetAddress = `${targetHost}:${targetPort}`;
  }
  
  if (!req.body.sourceAddress || !req.body.targetAddress) {
    return res.status(400).json({ 
      success: false, 
      message: 'Source address and target address are required' 
    });
  }
  
  // Windows命名管道格式化
  if (req.body.forwardingType === 'windows_pipe' && !req.body.sourceAddress.startsWith('\\\\.\\pipe\\')) {
    req.body.sourceAddress = formatWindowsNamedPipe(req.body.sourceAddress);
  }
  if (req.body.forwardingType === 'windows_pipe' && !req.body.targetAddress.startsWith('\\\\.\\pipe\\')) {
    req.body.targetAddress = formatWindowsNamedPipe(req.body.targetAddress);
  }
  
  // Generate a unique ID
  const id = Date.now().toString();
  
  const newRule = {
    id,
    sourceAddress: req.body.sourceAddress,
    targetAddress: req.body.targetAddress,
    forwardingType: req.body.forwardingType || 'tcp',
    // 保留旧字段以保持兼容性
    sourceIP: req.body.sourceIP,
    sourcePort: req.body.sourcePort,
    targetHost: req.body.targetHost,
    targetPort: req.body.targetPort,
    active: true,
    status: 'new'
  };
  
  forwardingRules.push(newRule);
  saveConfig();
  
  // Start forwarding immediately
  startSocketForwarding(newRule);
  
  res.redirect('/');
});

app.post('/toggle/:id', (req, res) => {
  const { id } = req.params;
  const rule = forwardingRules.find(r => r.id === id);
  
  if (rule) {
    rule.active = !rule.active;
    
    if (rule.active) {
      startSocketForwarding(rule);
    } else {
      stopForwarding(id);
    }
    
    saveConfig();
  }
  
  res.redirect('/');
});

app.post('/delete/:id', (req, res) => {
  const { id } = req.params;
  
  // First stop forwarding if active
  stopForwarding(id);
  
  // Remove from rules
  forwardingRules = forwardingRules.filter(r => r.id !== id);
  saveConfig();
  
  res.redirect('/');
});

// Start the server
app.listen(PORT, () => {
  console.log(`Management UI running at http://localhost:${PORT}`);
  
  // Load existing config and start forwarding
  loadConfig();
  startAllForwarding();
  
  // 开始监控系统端口
  startPortMonitoring();
});

// Handle graceful shutdown
process.on('SIGINT', () => {
  console.log('Shutting down...');
  stopAllForwarding();
  process.exit(0);
}); 