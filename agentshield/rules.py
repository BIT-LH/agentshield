"""内置规则目录。

规则按类别组织：

======================  ==========================================================
类别 id                 说明
======================  ==========================================================
prompt_injection       提示注入 / 指令劫持（针对 AI 技能与 Agent 的特殊风险）
credential_access      凭据与密钥访问
exfiltration           数据外泄
remote_execution       远程代码执行
persistence            持久化 / 自启动
privilege              过度权限
obfuscation            代码混淆与隐藏载荷
supply_chain           供应链风险
destructive            破坏性操作
======================  ==========================================================

语言标签：``python`` / ``javascript`` / ``shell`` / ``markdown`` / ``any``。
``any`` 表示对所有文本文件生效。
"""

from __future__ import annotations

from typing import List

from .models import Rule, Severity

#: 类别 -> 中文名
CATEGORY_LABELS = {
    "prompt_injection": "提示注入",
    "credential_access": "凭据访问",
    "exfiltration": "数据外泄",
    "remote_execution": "远程执行",
    "persistence": "持久化",
    "privilege": "过度权限",
    "obfuscation": "代码混淆",
    "supply_chain": "供应链",
    "destructive": "破坏性操作",
    "manifest": "清单声明",
    "custom": "自定义",
}

PY = ["python"]
JS = ["javascript"]
#: Shell 规则同样适用于 Python / JS 源码与 JSON / 文本配置 ——
#: npm 的 postinstall、Python 里内嵌的 curl 命令、README 里的示例都藏在这里。
SH = ["shell", "json", "text", "python", "javascript"]
MD = ["markdown"]
ANY = ["any"]
PY_JS = ["python", "javascript"]


def _r(
    rid: str,
    title: str,
    severity: Severity,
    category: str,
    pattern: str,
    description: str,
    remediation: str,
    languages: List[str] = None,
    message: str = "检测到可疑内容：{match}",
    tags: List[str] = None,
    confidence: str = "high",
    cwe: str = None,
    case_sensitive: bool = False,
) -> Rule:
    return Rule(
        id=rid,
        title=title,
        severity=severity,
        category=category,
        pattern=pattern,
        description=description,
        remediation=remediation,
        languages=languages if languages is not None else list(ANY),
        message=message or "命中规则 {rule_id}：{title}",
        tags=tags or [],
        confidence=confidence,
        cwe=cwe,
        case_sensitive=case_sensitive,
    )


BUILTIN_RULES: List[Rule] = [
    # ------------------------------------------------------------------
    # 提示注入 —— AI 技能 / Agent 特有
    # ------------------------------------------------------------------
    _r(
        "AS-PI-001",
        "技能指令中试图覆盖模型既有指令",
        Severity.CRITICAL,
        "prompt_injection",
        r"(?:ignore|disregard|forget|override)\s+(?:all\s+|any\s+)?"
        r"(?:the\s+)?(?:previous|prior|above|earlier|preceding|system)\s+"
        r"(?:instructions?|prompts?|rules?|directions?)",
        "技能正文中出现「忽略之前的指令」类措辞，这是典型的提示注入 (prompt injection) 手法。",
        "删除覆盖既有指令的措辞；技能应只描述自身职责，不应试图重定义模型行为。",
        MD + ANY,
        message="检测到覆盖既有系统指令的措辞：{match}",
        tags=["提示注入", "AI 特有"],
        cwe="CWE-77",
    ),
    _r(
        "AS-PI-002",
        "技能指令中尝试解除模型安全约束",
        Severity.CRITICAL,
        "prompt_injection",
        r"(?:you\s+are\s+now|from\s+now\s+on\s+you\s+are|act\s+as)\s+"
        r"(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|DAN)\b"
        r"|developer\s+mode\s+enabled"
        r"|\bignore\s+your\s+(?:safety|content)\s+(?:policy|guidelines?|rules?)",
        "技能试图让模型进入无限制模式，属于拒绝服务（refusal bypass）型提示注入。",
        "移除越权指令；如需敏感操作，走显式的人机确认流程而非在提示里绕过限制。",
        MD + ANY,
        message="检测到解除安全约束的措辞：{match}",
        tags=["提示注入", "越狱"],
        cwe="CWE-77",
    ),
    _r(
        "AS-PI-003",
        "技能中隐藏（不可见）给模型的指令",
        Severity.HIGH,
        "prompt_injection",
        r"<!--[^>]*?(?:ignore|system\s+instruction|do\s+not\s+(?:tell|mention|inform|reveal)"
        r"|silently|without\s+(?:telling|informing|asking)|secretly|hidden\s+instruction)[^>]*?-->",
        "HTML 注释中藏有针对模型的指令。用户看不到，但模型会读到。",
        "移除所有不可见的模型指令；面向用户的说明不应藏在注释里。",
        MD + ANY,
        message="注释中隐藏了针对模型的指令：{match}",
        tags=["提示注入", "隐藏指令"],
        cwe="CWE-77",
    ),
    _r(
        "AS-PI-004",
        "技能要求模型对用户隐瞒行为",
        Severity.HIGH,
        "prompt_injection",
        r"(?:do\s+not|don't|never)\s+(?:tell|inform|notify|mention\s+to|reveal\s+to|disclose\s+to)"
        r"\s+(?:the\s+)?(?:user|human|operator|owner)\b"
        r"|without\s+(?:telling|informing|notifying|asking)\s+(?:the\s+)?(?:user|human)",
        "技能要求模型对使用者隐瞒其行为，属于恶意或高度可疑的技能设计。",
        "删除隐瞒要求；技能的全部行为都应可被用户看到。",
        MD + ANY,
        message="技能要求对用户隐瞒行为：{match}",
        tags=["提示注入", "隐瞒"],
        cwe="CWE-77",
    ),
    _r(
        "AS-PI-005",
        "把外部获取的内容当作指令执行",
        Severity.HIGH,
        "prompt_injection",
        r"(?:prompt|system_prompt|systemPrompt|instructions)\s*[:=]\s*"
        r"(?:f?['\"].*\{?\s*(?:response|res|text|body|content|html|output)\b)"
        r"|(?:response|res|text|body|content)\s*[,)]\s*.*?append\s*\(\s*(?:prompt|system)",
        "把 HTTP 响应体直接拼进提示词，等于让远端内容对模型发号施令（间接提示注入）。",
        "对外部内容做清洗与转义，并以数据块而非指令块的形式注入；对内容中的指令性语句显式标注为不可信。",
        PY_JS,
        message="外部响应内容被直接拼入提示词：{match}",
        tags=["提示注入", "间接注入"],
        cwe="CWE-77",
    ),
    _r(
        "AS-PI-006",
        "读取用户敏感对话历史并外发",
        Severity.CRITICAL,
        "prompt_injection",
        r"(?:\.claude\.json|\.claude(?:/|\\\\)(?:projects|history|todos)"
        r"|conversation(?:s)?\.jsonl|chat\s*history|\.codex/|sessions?/.*\.jsonl)",
        "技能访问本地 AI 工具的会话历史或配置，其中可能含密钥与私密对话。",
        "只读取本技能自身所需的数据；如确需上下文，先征得用户同意并限定范围。",
        PY_JS + SH,
        message="访问了本地 AI 工具的会话/配置文件：{match}",
        tags=["提示注入", "数据窃取"],
        cwe="CWE-522",
    ),

    # ------------------------------------------------------------------
    # 凭据访问
    # ------------------------------------------------------------------
    _r(
        "AS-CRED-001",
        "读取 SSH 私钥",
        Severity.CRITICAL,
        "credential_access",
        r"(?:\.ssh(?:[/\\]|['\"]\s*,\s*['\"])(?:id_rsa|id_dsa|id_ecdsa|id_ed25519|identity|authorized_keys)\b"
        r"|\.ssh[/\\]authorized_keys)"
        r"|(?:open|readFileSync|readFile|cat)\s*\(\s*['\"][^'\"]*\.ssh[/\\]",
        "代码读取了 SSH 私钥或授权公钥文件。",
        "不要访问 SSH 密钥；如确需签名，请改用 ssh-agent 转发或专用密钥服务。",
        PY_JS + SH,
        message="访问 SSH 私钥路径：{match}",
        tags=["凭据", "SSH"],
        cwe="CWE-522",
    ),
    _r(
        "AS-CRED-002",
        "读取云厂商凭据文件",
        Severity.CRITICAL,
        "credential_access",
        r"\.aws[/\\](?:credentials|config)\b"
        r"|\.config[/\\]gcloud[/\\]"
        r"|\.azure[/\\]accessTokens\.json"
        r"|\.kube[/\\]config\b"
        r"|\.docker[/\\]config\.json"
        r"|\.netrc\b"
        r"|\.config[/\\]gh[/\\]hosts\.yml",
        "代码读取了云厂商 / 容器编排 / GitHub / Docker 的凭据文件。",
        "改用标准凭据链（环境变量、实例角色、CLI 登录态）；确需读文件时限定到具体条目并立即脱敏。",
        PY_JS + SH,
        message="访问云/容器凭据文件：{match}",
        tags=["凭据", "云"],
        cwe="CWE-522",
    ),
    _r(
        "AS-CRED-003",
        "读取项目 .env 环境变量文件",
        Severity.MEDIUM,
        "credential_access",
        r"(?:open|readFileSync|readFile|cat)\s*\(\s*['\"][^'\"]*\.env(?:\.[\w-]+)?['\"]"
        r"|(?:readFileSync|readFile)\s*\(\s*['\"][^'\"]*\.env(?:\.[\w-]+)?['\"]"
        r"|cat\s+[^\n]*\.env(?:\.[\w-]+)?(?:\s|$)",
        "代码直接读取 .env 文件，其中通常包含 API Key 与数据库口令。",
        "优先使用进程环境变量（已注入的部分）；若必须读文件，只取白名单键名并禁止外发。",
        PY_JS + SH,
        message="读取 .env 文件：{match}",
        tags=["凭据", "环境变量"],
        confidence="medium",
        cwe="CWE-522",
    ),
    _r(
        "AS-CRED-004",
        "全量导出进程环境变量",
        Severity.HIGH,
        "credential_access",
        r"dict\s*\(\s*os\.environ\s*\)"
        r"|os\.environ\.copy\s*\(\s*\)"
        r"|JSON\.stringify\s*\(\s*process\.env\s*\)"
        r"|Object\.(?:entries|keys|assign)\s*\(\s*process\.env\s*\)",
        "把整个环境变量表导出或整体序列化，通常意味着不区分哪些密钥可以外发。",
        "改为按需读取白名单变量；任何需要外发的值先脱敏。",
        PY_JS,
        message="全量导出环境变量：{match}",
        tags=["凭据", "环境变量"],
        cwe="CWE-200",
    ),
    _r(
        "AS-CRED-005",
        "读取浏览器用户数据目录",
        Severity.CRITICAL,
        "credential_access",
        r"(?:Chrome|Chromium|Edge|Brave|Firefox)[/\\](?:User Data|Default|Profiles)"
        r"|(?:Cookies|Login\s*Data|Local\s*State|key[34]\.db|cookies\.sqlite)"
        r"|Application\s*Support[/\\](?:Google/)?Chrome",
        "代码访问浏览器配置目录，可用于窃取 Cookie、会话与保存的密码。",
        "严禁访问浏览器数据目录；如需浏览器自动化，请使用用户显式授权的独立 profile。",
        PY_JS + SH,
        message="访问浏览器用户数据：{match}",
        tags=["凭据", "浏览器"],
        cwe="CWE-522",
    ),
    _r(
        "AS-CRED-006",
        "读取密码管理器或令牌存储",
        Severity.CRITICAL,
        "credential_access",
        r"(?:login-keyring|loginctl\s+show-password|secret-tool\s+lookup)"
        r"|\.password-store|\.keyring[/\\]"
        r"|1Password|bitwarden",
        "访问系统密钥环或密码管理器数据。",
        "不要访问密码管理器；让用户在其自己的客户端中完成授权。",
        SH,
        message="访问密码管理器/密钥环：{match}",
        tags=["凭据"],
        cwe="CWE-522",
    ),

    # ------------------------------------------------------------------
    # 数据外泄
    # ------------------------------------------------------------------
    _r(
        "AS-EXF-001",
        "向可疑回收集发数据",
        Severity.CRITICAL,
        "exfiltration",
        r"https?://(?:[\w.-]*\.)?(?:webhook\.site|requestbin\.(?:com|net)|pipedream\.net"
        r"|burpcollaborator\.net|interact\.sh|oast\.(?:pro|live|site|fun|me)"
        r"|ngrok\.io|ngrok-free\.app|localtunnel\.me|serveo\.net"
        r"|pastebin\.com/api|transfer\.sh|termbin\.com|0x0\.st|file\.io"
        r"|beeceptor\.com|requestcatcher\.com)",
        "代码向典型的「一次性收件箱」/ 隧道服务 POST 数据，这是数据外泄的强信号。",
        "移除对外部收集点的请求；确需上报，请使用组织自有且经过审计的端点。",
        PY_JS + SH,
        message="向可疑的数据收集端点发送请求：{match}",
        tags=["外泄", "IOC"],
        cwe="CWE-200",
    ),
    _r(
        "AS-EXF-002",
        "对凭据类内容做 Base64 编码后外发",
        Severity.CRITICAL,
        "exfiltration",
        r"(?:base64\.b64encode|btoa|Buffer\.from\s*\([^)]*\)\.toString\s*\(\s*['\"]base64['\"]\s*\)"
        r"|base64\.encodebytes|base64\.urlsafe_b64encode)"
        r"[\s\S]{0,160}?"
        r"(?:requests\.(?:post|put)|urlopen|httpx\.|axios|fetch\s*\()"
        r"|(?:requests\.(?:post|put)|urlopen|axios\.(?:post|put)|fetch\s*\([^)]*method\s*:\s*['\"]post)"
        r"[\s\S]{0,160}?"
        r"(?:base64\.b64encode|btoa|toString\s*\(\s*['\"]base64)",
        "先把数据编码再发送 —— 编码是外泄行为最常见的伪装手段。",
        "删除编码后外发的路径；审查所有出网请求的目标域名。",
        PY_JS,
        message="Base64 编码内容被外发：{match}",
        tags=["外泄", "混淆"],
        cwe="CWE-200",
    ),
    _r(
        "AS-EXF-003",
        "上传本地文件到外部服务",
        Severity.HIGH,
        "exfiltration",
        r"curl\b[^\n]*\s(?:-[A-Za-z]*[Ttf][A-Za-z]*|--upload-file|--form|-F)\s"
        r"|requests\.(?:post|put)\s*\(\s*files\s*="
        r"|(?:scp|rsync)\s+[^\n]*\s+[^\s]+@[^\s]+:",
        "把本地文件上传到外部服务器。",
        "确认上传目标可信且经过审计；对上传内容做分类与脱敏。",
        PY_JS + SH,
        message="存在文件上传到外部服务的行为：{match}",
        tags=["外泄", "文件上传"],
        confidence="medium",
        cwe="CWE-200",
    ),
    _r(
        "AS-EXF-004",
        "反向连接 / 建立对外通道",
        Severity.CRITICAL,
        "exfiltration",
        r"\bnc\s+(?:-[a-z]*e[a-z]*\s|-[a-z]*l[a-z]*\s)"
        r"|socat\b[^\n]*\b(?:exec|fork)\b"
        r"|socket\.socket\s*\([^)]*\)[^\n]{0,120}\.connect\s*\("
        r"|(?:bash\s+-i\s*>&|/dev/tcp/)",
        "建立反向 shell 或对外 TCP 通道，是典型的远控行为。",
        "删除反向连接逻辑；如需远程调试，改用经过审计的隧道并限定来源 IP。",
        PY_JS + SH,
        message="建立对外通道/反向连接：{match}",
        tags=["外泄", "后门"],
        cwe="CWE-506",
    ),
    _r(
        "AS-EXF-005",
        "把密钥或令牌写入日志",
        Severity.HIGH,
        "exfiltration",
        r"(?:print|console\.log|logger?\.(?:info|debug|warn|error)|logging\.(?:info|debug|warn|error))"
        r"\s*\([^)\n]{0,120}?"
        r"(?:api[_-]?key|secret|token|password|passwd|credential|authorization|bearer)",
        "敏感信息被写入日志，日志通常会被集中收集并长期留存。",
        "日志中对密钥做掩码（只保留后 4 位）；改为通过密钥管理服务获取。",
        PY_JS,
        message="疑似将敏感信息写入日志：{match}",
        tags=["外泄", "日志"],
        confidence="medium",
        cwe="CWE-532",
    ),
    _r(
        "AS-EXF-006",
        "构造动态外发 URL（绕过静态域名审查）",
        Severity.MEDIUM,
        "exfiltration",
        r"(?:requests\.(?:post|put|get)|urlopen|httpx\.(?:post|put|get)|fetch|axios)"
        r"\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*\+|base_url\s*\+|url\s*\+\s*)"
        r"|(?:url|endpoint|host|target)\s*=\s*(?:os\.environ|getenv|process\.env)",
        "请求地址由变量或环境变量动态拼接，静态审查无法判断实际目标。",
        "使用域名白名单校验；对最终 URL 做解析后再放行。",
        PY_JS,
        message="出网地址由动态变量拼接：{match}",
        tags=["外泄", "动态地址"],
        confidence="medium",
        cwe="CWE-200",
    ),

    # ------------------------------------------------------------------
    # 远程代码执行
    # ------------------------------------------------------------------
    _r(
        "AS-RCE-001",
        "动态求值（eval）",
        Severity.HIGH,
        "remote_execution",
        r"(?<![\w.$])eval\s*\(",
        "eval 会执行运行时构造的字符串，是最常见的代码注入入口。",
        "改用 ast.literal_eval / JSON.parse 等安全解析；确实需要动态执行时对输入做白名单校验。",
        PY_JS,
        message="使用了 eval：{match}",
        tags=["RCE"],
        cwe="CWE-95",
    ),
    _r(
        "AS-RCE-002",
        "动态执行代码（exec）",
        Severity.HIGH,
        "remote_execution",
        r"(?<![\w.$])exec\s*\(",
        "exec 执行任意 Python 代码。",
        "避免动态执行；改用受限的函数映射表或 ast.literal_eval。",
        PY,
        message="使用了 exec：{match}",
        tags=["RCE"],
        cwe="CWE-95",
    ),
    _r(
        "AS-RCE-003",
        "调用系统 shell 执行命令",
        Severity.HIGH,
        "remote_execution",
        r"os\.system\s*\(|subprocess\.(?:run|call|check_output|Popen)\s*\([^\n]*shell\s*=\s*True"
        r"|child_process\.exec(?:Sync)?\s*\(",
        "以 shell 方式拼接并执行命令，存在命令注入风险。",
        "使用参数数组形式（shell=False），并对参数做白名单校验。",
        PY_JS + SH,
        message="以 shell 方式执行命令：{match}",
        tags=["RCE", "命令注入"],
        cwe="CWE-78",
    ),
    _r(
        "AS-RCE-004",
        "下载并直接执行远程脚本",
        Severity.CRITICAL,
        "remote_execution",
        r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|k|d)?sh\b"
        r"|(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:python[23]?|node|perl|ruby)\b"
        r"|iwr\b[^\n|]*\|\s*iex\b",
        "从网络拉取内容并直接执行 —— 远端内容可随时被替换为恶意载荷。",
        "下载后校验固定哈希或签名再执行；优先使用包管理器与锁文件。",
        SH,
        message="下载并直接执行远程脚本：{match}",
        tags=["RCE", "供应链"],
        cwe="CWE-494",
    ),
    _r(
        "AS-RCE-005",
        "反序列化不可信数据",
        Severity.HIGH,
        "remote_execution",
        r"pickle\.loads?\s*\(|marshal\.loads\s*\(|yaml\.load\s*\((?![^\n]*SafeLoader)"
        r"|(?:node:)?serialize\.unserialize\s*\(",
        "pickle / marshal / 非安全 yaml.load 在反序列化时可执行任意代码。",
        "改用 json 等数据格式；确需 YAML 时显式使用 yaml.safe_load。",
        PY,
        message="反序列化不可信数据：{match}",
        tags=["RCE", "反序列化"],
        cwe="CWE-502",
    ),
    _r(
        "AS-RCE-006",
        "JavaScript 动态代码构造",
        Severity.HIGH,
        "remote_execution",
        r"(?<![\w.$])new\s+Function\s*\(|(?<![\w.$])Function\s*\(\s*['\"]"
        r"|vm\.runInNewContext\s*\(|vm\.runInThisContext\s*\(",
        "通过 Function 构造器或 vm 执行字符串代码。",
        "改为直接调用函数；如需沙箱，使用隔离进程而非 vm。",
        JS,
        message="JavaScript 动态代码执行：{match}",
        tags=["RCE"],
        cwe="CWE-95",
    ),
    _r(
        "AS-RCE-007",
        "拼接字符串后执行（命令注入）",
        Severity.HIGH,
        "remote_execution",
        r"(?:os\.system|subprocess\.\w+|child_process\.exec(?:Sync)?)\s*\([^\n]*"
        r"(?:\+\s*\w+|\$\{|\bf['\"]|\bf\"|%s\s*%)",
        "命令字符串由变量拼接而成，外部输入可改变命令结构。",
        "使用参数化调用；对所有动态片段做严格白名单校验。",
        PY_JS,
        message="拼接后的命令被执行：{match}",
        tags=["RCE", "命令注入"],
        cwe="CWE-78",
    ),
    _r(
        "AS-RCE-008",
        "对下载的二进制直接赋予执行权限并运行",
        Severity.CRITICAL,
        "remote_execution",
        r"(?:curl|wget)\b[^\n]*?(?:-o|--output)\s+\S+[\s\S]{0,200}?chmod\s+\+x"
        r"|(?:curl|wget)\b[^\n]*?[\s\S]{0,200}?chmod\s+\+x[\s\S]{0,80}?(?:\./|/tmp/)",
        "下载远端二进制、赋予执行权限并运行，中间没有完整性校验。",
        "校验哈希/签名后再执行；优先使用包管理器安装依赖。",
        SH,
        message="下载未经校验的二进制并执行：{match}",
        tags=["RCE", "供应链"],
        cwe="CWE-494",
    ),

    # ------------------------------------------------------------------
    # 持久化
    # ------------------------------------------------------------------
    _r(
        "AS-PER-001",
        "写入 Shell 启动文件",
        Severity.HIGH,
        "persistence",
        r"(?:\.bashrc|\.bash_profile|\.zshrc|\.profile|\.config[/\\]fish)"
        r"|(?:>>?|tee)\s+[^\n]*\.bashrc"
        r"|(?:append|write|extend)\s*\([^\n]*\.bashrc",
        "修改用户的 Shell 启动文件，命令会在每次打开终端时自动执行。",
        "不要修改用户启动文件；需要常驻能力时使用受管的服务定义并征得用户同意。",
        PY_JS + SH,
        message="写入 Shell 启动文件：{match}",
        tags=["持久化"],
        cwe="CWE-506",
    ),
    _r(
        "AS-PER-002",
        "安装计划任务 / 定时任务",
        Severity.HIGH,
        "persistence",
        r"\bcrontab\b|\bat\s+\+cron\b|schtasks\s+/create|systemd-run\b",
        "创建定时任务实现长期驻留。",
        "使用用户显式授权的调度方式，并在文档中说明将创建什么。",
        PY_JS + SH,
        message="创建计划任务：{match}",
        tags=["持久化"],
        cwe="CWE-506",
    ),
    _r(
        "AS-PER-003",
        "注册系统服务 / 开机自启",
        Severity.HIGH,
        "persistence",
        r"systemctl\s+(?:enable|--user\s+enable)|/etc/systemd/system/"
        r"|LaunchAgents|Library/LaunchDaemons"
        r"|reg\s+add\s+[^\n]*\\\\Run\b",
        "注册系统服务或开机自启项，是典型的恶意持久化手法。",
        "避免系统级持久化；如业务确需，请走系统管理员的正式流程。",
        PY_JS + SH,
        message="注册系统服务/自启项：{match}",
        tags=["持久化"],
        cwe="CWE-506",
    ),
    _r(
        "AS-PER-004",
        "修改 Shell 配置文件（rc）以实现自启",
        Severity.HIGH,
        "persistence",
        r"(?:>>?|tee)\s+(?:[^\n]*)?~?/?\.(?:bashrc|zshrc|bash_profile|profile)\b"
        r"|open\s*\(\s*['\"][^'\"]*\.(?:bashrc|zshrc|bash_profile)['\"][^\n]*['\"]\s*['\"]a",
        "向 rc 文件追加内容实现自启。",
        "不要修改用户 Shell 配置。",
        PY_JS + SH,
        message="向 rc 文件追加内容：{match}",
        tags=["持久化"],
        cwe="CWE-506",
    ),

    # ------------------------------------------------------------------
    # 过度权限
    # ------------------------------------------------------------------
    _r(
        "AS-PRV-001",
        "使用 sudo / 提权执行",
        Severity.MEDIUM,
        "privilege",
        r"(?<![\w/])sudo\s+\S|(?<![\w])os\.setuid\s*\(|chmod\s+777\b|chmod\s+[+]s\b",
        "技能以高权限运行，可能读取或破坏系统级资源。",
        "以最小权限运行；把需要提权的步骤交还给用户手动执行。",
        SH + PY,
        message="存在提权执行：{match}",
        tags=["权限"],
        confidence="medium",
        cwe="CWE-250",
    ),
    _r(
        "AS-PRV-002",
        "递归删除高危路径",
        Severity.CRITICAL,
        "destructive",
        r"rm\s+(?:-[a-zA-Z]*\s+)*-[a-zA-Z]*[rR][a-zA-Z]*f?[a-zA-Z]*\s+(?:/|~|\$HOME|\*)\s*$"
        r"|rm\s+-[rR]f\s+(?:/|~|\$HOME)(?:\s|$)"
        r"|Remove-Item\b[^\n]*-Recurse[^\n]*(?:\bC:\\|\$env:USERPROFILE)",
        "递归删除根目录或家目录。",
        "删除操作必须限定在明确的子目录内，并在删除前列出将被删除的路径。",
        SH,
        message="高危递归删除：{match}",
        tags=["破坏性"],
        cwe="CWE-732",
    ),
    _r(
        "AS-PRV-003",
        "修改文件属主或开放全局写权限",
        Severity.MEDIUM,
        "privilege",
        r"\bchown\s+(?:-R\s+)?(?:root|0)\b|chmod\s+(?:0?777|a\+rwx)\b",
        "改变文件属主或开放任意用户可写的权限。",
        "保持最小权限；共享文件使用受控的组权限而非全局可写。",
        SH,
        message="修改属主或开放全局写权限：{match}",
        tags=["权限"],
        confidence="medium",
        cwe="CWE-732",
    ),
    _r(
        "AS-PRV-004",
        "无条件删除数据库表或数据",
        Severity.CRITICAL,
        "destructive",
        r"DROP\s+(?:TABLE|DATABASE|SCHEMA)\b(?![^;]*\bIF\s+EXISTS\b\s+\w+\s*;?\s*--)"
        r"|TRUNCATE\s+TABLE\b(?![\s\S]{0,40}WHERE)"
        r"|\.dropDatabase\s*\(|\.drop\s*\(\s*\)",
        "无条件删除表或整库。",
        "生产环境禁用 DROP/TRUNCATE；测试数据用独立 schema 管理。",
        PY_JS,
        message="无条件删除表/数据：{match}",
        tags=["破坏性"],
        confidence="medium",
        cwe="CWE-89",
    ),

    # ------------------------------------------------------------------
    # 代码混淆
    # ------------------------------------------------------------------
    _r(
        "AS-OBF-001",
        "解码后直接执行（Base64 / Hex 载荷）",
        Severity.CRITICAL,
        "obfuscation",
        r"(?<![\w.])(?:eval|exec)\s*\(\s*(?:base64\.(?:b64decode|standard_b64decode|bytes_decode)|codecs\.decode)"
        r"|atob\s*\(\s*(?:atob|eval)\s*\("
        r"|eval\s*\(\s*atob\s*\("
        r"|Buffer\.from\s*\([^)]*['\"]base64['\"]\s*\)\s*\.toString\s*\(\s*\)[\s\S]{0,60}?eval"
        r"|exec\s*\(\s*base64\b|compile\s*\(\s*base64\b",
        "把编码内容解码后立即执行 —— 静态审查无法看到真实载荷。",
        "禁止编码载荷；所有可执行逻辑必须以明文源码形式提交并经过 review。",
        PY_JS + SH,
        message="存在解码后直接执行的行为：{match}",
        tags=["混淆", "载荷隐藏"],
        cwe="CWE-506",
    ),
    _r(
        "AS-OBF-002",
        "使用字符码数组构造字符串",
        Severity.HIGH,
        "obfuscation",
        r"String\.fromCharCode\s*\([^)]{40,}\)"
        r"|(?:chr|String\.fromCharCode)\s*\(\s*\d+\s*(?:,\s*\d+\s*){10,}"
        r"|\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){15,}",
        "用字符码拼装字符串是典型的代码混淆手法。",
        "使用可读的字符串字面量。",
        PY_JS,
        message="存在字符码拼接混淆：{match}",
        tags=["混淆"],
        cwe="CWE-506",
    ),
    _r(
        "AS-OBF-003",
        "运行时自解码 / 自修改代码",
        Severity.HIGH,
        "obfuscation",
        r"(?:codecs\.decode\s*\([^\n]*rot_?13|rot13|\.translate\s*\(\s*str\.maketrans)"
        r"|__import__\s*\(\s*['\"]os['\"]\s*\)\s*\.\s*system"
        r"|importlib\.import_module\s*\(\s*__import__",
        "运行时动态导入或 ROT13 解码，用于规避静态审查。",
        "使用静态导入与明文字符串。",
        PY,
        message="运行时自解码/动态导入：{match}",
        tags=["混淆"],
        cwe="CWE-506",
    ),

    # ------------------------------------------------------------------
    # 供应链
    # ------------------------------------------------------------------
    _r(
        "AS-SUP-001",
        "通过明文 HTTP 下载依赖",
        Severity.HIGH,
        "supply_chain",
        r"(?:pip[23]?\s+install|npm\s+(?:i|install)|curl\b[^\n|]*|wget\b[^\n|]*)\s+"
        r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)",
        "通过明文 HTTP 下载依赖，内容可在传输中被篡改。",
        "一律使用 HTTPS；对关键依赖固定版本与哈希。",
        SH + ANY,
        message="明文 HTTP 下载：{match}",
        tags=["供应链"],
        cwe="CWE-319",
    ),
    _r(
        "AS-SUP-002",
        "从 Git 仓库直接安装依赖（未固定版本）",
        Severity.MEDIUM,
        "supply_chain",
        r"pip\s+install\s+(?:git\+)?(?:https?://[^\s]*?\.git|git\+[^\s]*)"
        r"|pip3?\s+install\s+[^\s]*@\s*(?:git|https?://)"
        r"|npm\s+install\s+(?:git\+|github:)",
        "直接从 Git 仓库安装依赖，代码内容随时可变且未经审计。",
        "使用发布到包仓库的固定版本，并启用 lock 文件与哈希校验。",
        SH + ANY,
        message="从 Git 仓库直接安装依赖：{match}",
        tags=["供应链"],
        confidence="medium",
        cwe="CWE-1357",
    ),
    _r(
        "AS-SUP-003",
        "安装依赖时未指定版本",
        Severity.LOW,
        "supply_chain",
        r"pip3?\s+install\s+(?!--|\-r\b)[A-Za-z][\w.\-]*(?:\s|\s*$)"
        r"|npm\s+(?:i|install)\s+(?!--|-\-save-dev\b)[@a-z][\w@/.\-]*(?:\s|\s*$)",
        "未固定版本意味着每次安装都可能引入新代码。",
        "固定版本号并提交 lock 文件。",
        SH,
        message="依赖未固定版本：{match}",
        tags=["供应链"],
        confidence="low",
        cwe="CWE-1357",
    ),
    _r(
        "AS-SUP-004",
        "安装时执行来自网络的内容",
        Severity.HIGH,
        "supply_chain",
        r"pip3?\s+install\s+[^\n]*(?:--trusted-host|--index-url\s+http)"
        r"|npm\s+(?:i|install)\s+[^\n]*--registry\s+http"
        r"|--allow-untrusted|--unsafe-perm|--allow-root",
        "放宽安装校验或指向非官方源，等同于放弃供应链校验。",
        "使用官方源并保持校验开启；如需私有源请配置证书与凭据。",
        SH,
        message="安装时放宽校验：{match}",
        tags=["供应链"],
        cwe="CWE-494",
    ),

    # ------------------------------------------------------------------
    # 破坏性 / 通用
    # ------------------------------------------------------------------
    _r(
        "AS-DST-001",
        "强制推送覆盖远端历史",
        Severity.HIGH,
        "destructive",
        r"git\s+push\s+(?:[^\n]*--force(?:-with-lease)?\b)(?![^\n]*--dry-run)"
        r"|git\s+push\s+[^\n]*\s-f\b",
        "强制推送可能覆盖他人提交与远端历史。",
        "优先使用 --force-with-lease；共享分支禁止强推。",
        SH,
        message="强制推送覆盖远端历史：{match}",
        tags=["破坏性", "Git"],
        cwe="CWE-400",
    ),
    _r(
        "AS-DST-002",
        "磁盘级写入或格式化",
        Severity.CRITICAL,
        "destructive",
        r"\bmkfs(?:\.\w+)?\b|\bdd\s+[^\n]*\bof=/dev/"
        r"|DiskPart|diskpart\s+[^\n]*clean",
        "对块设备执行格式化或裸写，会摧毁数据。",
        "在数据处理脚本中禁止出现块设备级别的写操作。",
        SH,
        message="存在块设备级写入/格式化：{match}",
        tags=["破坏性"],
        cwe="CWE-732",
    ),
    _r(
        "AS-DST-003",
        "硬编码的密钥 / Token",
        Severity.HIGH,
        "credential_access",
        r"(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}"
        r"|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}"
        r"|AIza[0-9A-Za-z_\-]{30,}"
        r"|xox[baprs]-[A-Za-z0-9\-]{10,})",
        "源码中出现形似真实密钥的字符串，一旦提交即等于公开泄露。",
        "立即吊销该密钥并改用环境变量或密钥管理服务；提交前配置 secret 扫描。",
        PY_JS + SH + MD + ANY,
        message="疑似硬编码密钥：{match}",
        tags=["凭据", "密钥泄露"],
        cwe="CWE-798",
    ),
]


def get_rules() -> List[Rule]:
    """返回内置规则列表（副本，避免调用方修改全局状态）。"""
    return [Rule.from_dict(r.to_dict()) for r in BUILTIN_RULES]
