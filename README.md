# takeover CoreDNS Plugin

takeover是一个CoreDNS插件，用于检测域名是否过期或可能存在子域名接管漏洞。

## 功能特性

- **域名过期检测**：检查域名是否即将过期，并在过期前发出警告
- **子域名接管检测**：检测子域名是否容易受到接管攻击
- **域名可用性检测**：对于已解析的域名，通过阿里云API检测是否可购买
- **支持多种云服务**：AWS、Azure、Cloudflare、GitHub Pages、Heroku等
- **可配置的检查选项**：可以根据需要启用或禁用特定检查
- **结果缓存**：避免重复检查，提高性能

## 安装方法

1. 克隆CoreDNS仓库：
   ```bash
   git clone https://github.com/coredns/coredns.git
   cd coredns
   ```

2. 编辑`plugin.cfg`文件，添加DomainHunter插件：
   ```bash
   echo "takeover:github.com/Dk0n9/takeover" >> plugin.cfg
   ```

3. 构建CoreDNS：
   ```bash
   make
   ```

## 配置选项

| 配置项 | 类型 | 默认值 | 描述 |
|--------|------|--------|------|
| `check_resolved` | bool | `true` | 是否启用域名解析检查 |
| `check_takeover` | bool | `true` | 是否启用子域名接管检查 |
| `cache_ttl` | duration | `1h` | 检查结果缓存时间 |
| `webhook_url` | string | `""` | Webhook通知URL |
| `webhook_type` | string | `generic` | Webhook类型: `generic`, `dingtalk`, `feishu` |

## 使用示例

### 基本配置

```
.:53 {
    log
    forward . 8.8.8.8 1.1.1.1
    takeover {
        check_resolved on
        check_takeover on
        cache_ttl 24h
    }
}
```

### 配置钉钉Webhook通知

```
.:53 {
    log
    forward . 8.8.8.8 1.1.1.1
    takeover {
        check_resolved on
        check_takeover on
        cache_ttl 24h
        webhook_url https://oapi.dingtalk.com/robot/send?access_token=your_token
        webhook_type dingtalk
    }
}
```

### 配置飞书Webhook通知

```
.:53 {
    log
    forward . 8.8.8.8 1.1.1.1
    takeover {
        check_resolved on
        check_takeover on
        cache_ttl 24h
        webhook_url https://open.feishu.cn/open-apis/bot/v2/hook/your_webhook_key
        webhook_type feishu
    }
}
```


## 支持的子域名接管检查

- AWS/Elastic Beanstalk
- AWS S3 Bucket
- Anima
- ~~Azure Cloud Services (cloudapp.net)~~ Not Vulnerable
- Bitbucket
- Cloudflare Workers/Pages
- Discourse
- GitHub Pages
- ~~Heroku Apps~~ Not Vulnerable
- Microsoft Azure
- Wordpress

## 注意事项

1. 插件目前使用简化的域名未解析检查实现。
2. 子域名接管检查基于已知的云服务提供商域名模式，可能无法检测所有类型的子域名接管漏洞。
3. 检查结果会被缓存，默认缓存时间为1天，可以通过`cache_ttl`配置项调整。

## 许可证

Apache License 2.0
