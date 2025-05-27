import { connect } from "cloudflare:sockets";

//////////////////////////////////////////////////////////////////////////配置区块////////////////////////////////////////////////////////////////////////
let 哎呀呀这是我的ID啊 = "shulng"; // 订阅路径
let 哎呀呀这是我的VL密钥 = "25284107-7424-40a5-8396-cdd0623f4f05"; // UUID

let 我的优选 = []; // 节点列表
let 我的优选TXT = ["https://raw.githubusercontent.com/shulng/shulng/refs/heads/main/ip.txt"]; // 优选TXT路径

let 我的节点名字 = "水灵"; // 节点名字

//////////////////////////////////////////////////////////////////////////网页入口////////////////////////////////////////////////////////////////////////
export default {
  async fetch(访问请求, env) {
    const 读取我的请求标头 = 访问请求.headers.get("Upgrade");
    const url = new URL(访问请求.url);
    if (!读取我的请求标头 || 读取我的请求标头 !== "websocket") {
      if (我的优选TXT.length > 0) {
        我的优选 = [
          ...new Set(
            (
              await Promise.all(
                我的优选TXT.map(async (url) => {
                  const response = await fetch(url);
                  return response.ok
                    ? (await response.text())
                      .split("\n")
                      .map((line) => line.trim())
                      .filter(Boolean)
                    : [];
                })
              )
            ).flat()
          ),
        ];
      }
      if (url.pathname === `/${哎呀呀这是我的ID啊}`) {
        const 用户代理 = 访问请求.headers.get("User-Agent").toLowerCase();
        const 配置生成器 = {
          v2ray: 生成通用配置,
          clash: 生成猫咪配置,
        };
        const 工具 = Object.keys(配置生成器).find((工具) => 用户代理.includes(工具));
        const 生成配置 = 配置生成器[工具];
        return new Response(生成配置(访问请求.headers.get("Host")), {
          status: 200,
          headers: { "Content-Type": "text/plain;charset=utf-8" },
        });
      }
    } else if (读取我的请求标头 === "websocket") {
      return await 升级WS请求(访问请求);
    }
  },
};
////////////////////////////////////////////////////////////////////////脚本主要架构//////////////////////////////////////////////////////////////////////
//第一步，读取和构建基础访问结构
async function 升级WS请求(访问请求) {
  const [客户端, WS接口] = new WebSocketPair(); //创建WS接口对象
  const 读取我的加密访问内容数据头 = 访问请求.headers.get("sec-websocket-protocol"); //读取访问标头中的WS通信数据
  const 解密数据 = 使用64位加解密(读取我的加密访问内容数据头); //解密目标访问数据，传递给TCP握手进程
  await 解析VL标头(解密数据, WS接口); //解析VL数据并进行TCP握手
  return new Response(null, { status: 101, webSocket: 客户端 }); //一切准备就绪后，回复客户端WS连接升级成功
}
function 使用64位加解密(还原混淆字符) {
  还原混淆字符 = 还原混淆字符.replace(/-/g, "+").replace(/_/g, "/");
  const 解密数据 = atob(还原混淆字符);
  const 解密_你_个_丁咚_咙_咚呛 = Uint8Array.from(解密数据, (c) => c.charCodeAt(0));
  return 解密_你_个_丁咚_咙_咚呛.buffer;
}
//第二步，解读VL协议数据，创建TCP握手
async function 解析VL标头(VL数据, WS接口, TCP接口) {
  if (验证VL的密钥(new Uint8Array(VL数据.slice(1, 17))) !== 哎呀呀这是我的VL密钥) {
    return null;
  }
  const 获取数据定位 = new Uint8Array(VL数据)[17];
  const 提取端口索引 = 18 + 获取数据定位 + 1;
  const 建立端口缓存 = VL数据.slice(提取端口索引, 提取端口索引 + 2);
  const 访问端口 = new DataView(建立端口缓存).getUint16(0);
  const 提取地址索引 = 提取端口索引 + 2;
  const 建立地址缓存 = new Uint8Array(VL数据.slice(提取地址索引, 提取地址索引 + 1));
  const 识别地址类型 = 建立地址缓存[0];
  let 地址长度 = 0;
  let 访问地址 = "";
  let 地址信息索引 = 提取地址索引 + 1;
  switch (识别地址类型) {
    case 1:
      地址长度 = 4;
      访问地址 = new Uint8Array(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度)).join(".");
      break;
    case 2:
      地址长度 = new Uint8Array(VL数据.slice(地址信息索引, 地址信息索引 + 1))[0];
      地址信息索引 += 1;
      访问地址 = new TextDecoder().decode(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      break;
    case 3:
      地址长度 = 16;
      const dataView = new DataView(VL数据.slice(地址信息索引, 地址信息索引 + 地址长度));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      访问地址 = ipv6.join(":");
      break;
  }
  const 写入初始数据 = VL数据.slice(地址信息索引 + 地址长度);

  try {
    TCP接口 = await connect({ hostname: 访问地址, port: 访问端口 });
    await TCP接口.opened;
  } catch {
    const NAT64地址 = 识别地址类型 === 1
      ? 转换IPv4到NAT64(访问地址)
      : 转换IPv4到NAT64(await 解析域名到IPv4(访问地址));
    TCP接口 = await connect({ hostname: NAT64地址, port: 访问端口 });
  }

  建立传输管道(WS接口, TCP接口, 写入初始数据);
}

// 将IPv4地址转换为NAT64 IPv6地址
function 转换IPv4到NAT64(ipv4地址) {
  const 部分 = ipv4地址.split(".");
  const 十六进制 = 部分.map(段 => parseInt(段, 10).toString(16).padStart(2, "0"));
  return `[2001:67c:2960:6464::${十六进制[0]}${十六进制[1]}:${十六进制[2]}${十六进制[3]}]`;
}

// 解析域名到IPv4地址
async function 解析域名到IPv4(域名) {
  const 响应 = await fetch(`https://cloudflare-dns.com/dns-query?name=${域名}&type=A`, {
    headers: { "Accept": "application/dns-json" }
  });
  const 结果 = await 响应.json();
  return 结果.Answer.find(记录 => 记录.type === 1).data;
}

function 验证VL的密钥(arr, offset = 0) {
  const uuid = (转换密钥格式[arr[offset + 0]] + 转换密钥格式[arr[offset + 1]] + 转换密钥格式[arr[offset + 2]] + 转换密钥格式[arr[offset + 3]] + "-" + 转换密钥格式[arr[offset + 4]] + 转换密钥格式[arr[offset + 5]] + "-" + 转换密钥格式[arr[offset + 6]] + 转换密钥格式[arr[offset + 7]] + "-" + 转换密钥格式[arr[offset + 8]] + 转换密钥格式[arr[offset + 9]] + "-" + 转换密钥格式[arr[offset + 10]] + 转换密钥格式[arr[offset + 11]] + 转换密钥格式[arr[offset + 12]] + 转换密钥格式[arr[offset + 13]] + 转换密钥格式[arr[offset + 14]] + 转换密钥格式[arr[offset + 15]]).toLowerCase();
  return uuid;
}
const 转换密钥格式 = [];
for (let i = 0; i < 256; ++i) {
  转换密钥格式.push((i + 256).toString(16).slice(1));
}

//第三步，创建客户端WS-CF-目标的传输通道并监听状态
async function 建立传输管道(WS接口, TCP接口, 写入初始数据) {
  // 建立连接和初始化
  WS接口.accept();
  await WS接口.send(new Uint8Array([0, 0]).buffer);

  // 获取TCP流读写器
  const 传输数据 = TCP接口.writable.getWriter();
  const 读取数据 = TCP接口.readable.getReader();

  // 写入初始数据（如果有）
  if (写入初始数据) await 传输数据.write(写入初始数据);

  // WebSocket消息转发到TCP
  WS接口.addEventListener("message", async (event) => {
    await 传输数据.write(event.data);
  });

  // TCP数据转发到WebSocket
  (async () => {
    while (true) {
      const { value: 返回数据, done } = await 读取数据.read();
      if (done) break;
      if (返回数据) await WS接口.send(返回数据);
    }
  })();
}

//////////////////////////////////////////////////////////////////////////订阅页面////////////////////////////////////////////////////////////////////////
let 转码 = "vl",
  转码2 = "ess",
  符号 = "://",
  小猫 = "cla",
  咪 = "sh";
function 生成通用配置(hostName) {
  if (我的优选.length === 0) {
    我的优选 = [`${hostName}:443`];
  }
  return 我的优选
    .map((获取优选) => {
      const [主内容, tls] = 获取优选.split("@");
      const [地址端口, 节点名字 = 我的节点名字] = 主内容.split("#");
      const 拆分地址端口 = 地址端口.split(":");
      const 端口 = 拆分地址端口.length > 1 ? Number(拆分地址端口.pop()) : 443;
      const 地址 = 拆分地址端口.join(":");
      const TLS开关 = tls === "notls" ? "security=none" : "security=tls";
      return `${转码}${转码2}${符号}${哎呀呀这是我的VL密钥}@${地址}:${端口}?encryption=none&${TLS开关}&sni=${hostName}&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${节点名字}`;
    })
    .join("\n");
}
function 生成猫咪配置(hostName) {
  if (我的优选.length === 0) {
    我的优选 = [`${hostName}:443`];
  }
  const 生成节点 = (我的优选) => {
    return 我的优选.map((获取优选) => {
      const [主内容, tls] = 获取优选.split("@");
      const [地址端口, 节点名字 = 我的节点名字] = 主内容.split("#");
      const 拆分地址端口 = 地址端口.split(":");
      const 端口 = 拆分地址端口.length > 1 ? Number(拆分地址端口.pop()) : 443;
      const 地址 = 拆分地址端口.join(":").replace(/^\[|\]/g, "");
      const TLS开关 = tls === "notls" ? "false" : "true";
      return {
        nodeConfig: `  - name: "${节点名字}-${地址}-${端口}"
    type: ${转码}${转码2}
    server: ${地址}
    port: ${端口}
    uuid: ${哎呀呀这是我的VL密钥}
    udp: false
    tls: ${TLS开关}
    network: ws
    servername: ${hostName}
    ws-opts:
      path: "/?ed=2560"
      headers:
        Host: ${hostName}`,
        proxyConfig: `      - "${节点名字}-${地址}-${端口}"`,
      };
    });
  };
  const 节点配置 = 生成节点(我的优选)
    .map((node) => node.nodeConfig)
    .join("\n");
  const 代理配置 = 生成节点(我的优选)
    .map((node) => node.proxyConfig)
    .join("\n");
  return `
dns:
  enable: true
  ipv6: true

  default-nameserver:
    - 8.8.8.8
    - 1.1.1.1

  listen: 0.0.0.0:1053
  use-hosts: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - '*.lan'

  nameserver:
    - 8.8.8.8
    - 1.0.0.1

proxies:
${节点配置}
proxy-groups:
  - name: "自动选择"
    type: url-test
    url: "https://www.google.com/generate_204"
    interval: 30
    tolerance: 50
    proxies:
${代理配置}
rules:
  - GEOIP,CN,DIRECT
  - MATCH,自动选择
`;
}