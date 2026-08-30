# YoLab Agent Skill Guard

**離線優先的 AI Agent Skill／指令檔安全、隱私與相容性稽核器。**

`skillguard` 讀取驅動 AI 編碼代理的那些檔案——`SKILL.md`、`AGENTS.md`、
`CLAUDE.md`、`.claude/` 技能與指令、`.cursor/rules/*.mdc`，以及一般的
Markdown instruction 檔——並回報藏在其中的風險信號：內嵌憑證、破壞性指令、
下載即執行、prompt injection 句型、路徑逃逸、失效參照、過度工具權限、
未固定的供應鏈相依。

它是單一靜態執行檔：絕不執行被掃描的內容、runtime 不碰網路、不打開你的
`.env`，並產生為 CI 設計的 byte-for-byte deterministic 報告。

[English README → README.md](README.md)

---

## 問題

Agent skill 是「用散文寫成的程式」。代理以高度信任讀取並照做，但這些檔案被
分享、fork、安裝時受到的審查，比 lockfile 裡任何一個相依都少。一個 skill
package 可能：

- 把**硬編碼 token** 帶進每一個 fork 與每一次模型上下文；
- 把**不可逆的清理指令**（硬重設、強制清除、資料表刪除）當成日常步驟；
- **把遠端腳本直接接進 shell**，等於把程式碼執行權交給明天控制那台主機的人；
- 內嵌 **prompt injection 句型**，要代理拋棄先前規則、或對使用者隱瞞動作；
- 參照**套件外的檔案**（上層目錄、絕對路徑、percent-encoding、symlink），
  審查者根本看不到實際載入的內容；
- 悄悄腐化：失效參照、無效 frontmatter、重複欄位。

一般工具鏈不會審這些檔案。skillguard 專門審。

## 功能

- **12 條偵測規則**（`ASG001`–`ASG012`）加上過期抑制的治理規則（`ASG900`）。
- **平台感知**：自動分類 `claude`／`codex`／`cursor`／`generic`，套用對應的
  manifest 要求。
- **可信任的嚴重度**：finding 的嚴重度只由規則決定。受掃描檔案裡的任何內容
  ——散文或程式碼區塊、引用區塊、警告詞、任何形式的禁止語句——都不能降低它、
  讓 finding 消失或改變 exit code。例外只能寫在設定檔裡：具名、附理由、可過期。
- **四種報告格式**——人類可讀 `text`、版本化 `json`、GitHub 可直接吃的
  `sarif`（2.1.0）、以及單檔自足、無障礙的 `html`——findings 完全一致。
- **Deterministic**：無時間戳記、無 map 亂序、無絕對路徑；相同輸入兩次執行
  產出 byte 完全相同。
- **設定即政策**：`.skillguard.yml` 支援網域與能力允許清單、逐規則嚴重度
  覆寫、必附理由且可過期的抑制（suppression）。
- **CI 原生**：exit code 0/1/2、`--fail-on` 門檻、供 shell 使用的 summary
  檔、Docker 型 GitHub Action。

## 安全模型（摘要）

| 承諾 | 落實方式 |
|---|---|
| 絕不執行被掃描內容 | 純文字分析，無 shell、無 eval、無渲染 |
| runtime 絕不使用網路 | 掃描器內不存在網路程式碼路徑 |
| 絕不讀取敏感檔案 | `.env*`、金鑰、資料庫、壓縮檔**依檔名跳過、從未開啟**，僅回報「存在且已跳過」 |
| symlink 絕不逃出掃描根目錄 | 先解析目標，再以檔案系統識別（`os.SameFile`）檢查包含關係後才允許讀取；絕不以字串小寫比對判定 |
| 絕不輸出機密原文 | 疑似憑證在所有格式一律遮蔽 |
| 絕不操控你的終端機 | 檔名、訊息，以及 CLI 自己的診斷訊息（含 `flag` 套件回顯的未知旗標名）在輸出前一律轉義；`--no-color` 輸出完全不含 ESC |
| 絕不宣稱惡意 | Heuristic findings 一律標示為需人工覆核的風險信號 |

詳見 [docs/security-model.md](docs/security-model.md)、
[docs/threat-model.md](docs/threat-model.md)、[docs/privacy.md](docs/privacy.md)。

## 30 秒上手

```bash
git clone https://github.com/Yakitori197/yolab-agent-skill-guard
cd yolab-agent-skill-guard
go build -o skillguard ./cmd/skillguard

./skillguard scan path/to/your/skills
```

## CLI

```bash
skillguard scan .                          # 完整掃描，text 報告
skillguard scan pkg --format sarif --output report.sarif
skillguard scan pkg --format html  --output report.html
skillguard scan pkg --fail-on medium       # 更嚴格的 CI 門檻
skillguard validate pkg                    # 只驗證結構／frontmatter／參照
skillguard rules                           # 列出規則目錄
skillguard explain ASG004                  # 深入解說單一規則
skillguard init                            # 產生 .skillguard.yml 範本
skillguard version
```

## GitHub Action

```yaml
jobs:
  skill-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      # 首次 release 後，請改釘到完整 commit SHA：
      - uses: Yakitori197/yolab-agent-skill-guard@<pinned-commit-sha>
        with:
          path: .
          fail-on: high
          format: sarif
          output: skillguard-report.sarif
```

Action **不需要任何 secret**、**不傳送任何內容**，只掃描 checkout 的
workspace。output 可以是新檔案，但它的直接父目錄必須已存在；Action 不會自動
建立目錄，也不會覆寫任何既有路徑。詳見
[docs/github-action.md](docs/github-action.md)。

## 支援的檔案

| 平台 | 檔案 |
|---|---|
| `claude` | `SKILL.md`（含其套件目錄內所有檔案）、`CLAUDE.md`、`.claude/skills/**`、`.claude/commands/*.md` |
| `codex` | `AGENTS.md` |
| `cursor` | `.cursor/rules/*.mdc`、任何 `*.mdc` |
| `generic` | 其他 `*.md`／`*.markdown` instruction 檔 |

## 規則摘要

| ID | 名稱 | 預設嚴重度 |
|---|---|---|
| ASG001 | Hardcoded Secret（硬編碼機密） | critical |
| ASG002 | Private Absolute Path（私人絕對路徑） | medium |
| ASG003 | Destructive Command（破壞性指令） | high |
| ASG004 | Remote Pipe Execution（下載即執行） | critical |
| ASG005 | Undeclared Network Access（未宣告網路存取） | medium |
| ASG006 | Excessive Tool Permission（過度工具權限） | high |
| ASG007 | Path Escape（路徑逃逸） | high |
| ASG008 | Missing Reference（失效參照） | medium |
| ASG009 | Invalid Manifest（無效 Manifest） | medium |
| ASG010 | Prompt Injection Signal（注入信號） | high |
| ASG011 | Unpinned Remote Dependency（未固定相依） | medium |
| ASG012 | Obfuscated Payload（混淆酬載） | high |
| ASG900 | Expired Suppression（過期抑制） | info |

Rule ID 一經公開即為穩定 API。完整說明見 [docs/rules.md](docs/rules.md)
或 `skillguard explain <ID>`。

## Exit codes

| 代碼 | 意義 |
|---|---|
| `0` | 掃描成功，沒有達到 `--fail-on` 門檻的 finding |
| `1` | 掃描成功，存在達到門檻的 finding |
| `2` | 設定、輸入或 runtime 錯誤（一律 fail closed） |

## 隱私承諾

skillguard 完全在你的機器上執行：不傳輸、不回報、無任何遙測或分析。常見存放
機密的檔案從未被開啟，報告中僅以「存在且已跳過」呈現；掃描文字中發現的疑似
機密在所有輸出格式一律遮蔽。完整政策見 [docs/privacy.md](docs/privacy.md)。

## 報告示範

由 `examples/risky-skill` 產生、已提交的 deterministic 報告：

- HTML：[docs/examples/risky-report.html](docs/examples/risky-report.html)
- SARIF：[docs/examples/risky-report.sarif](docs/examples/risky-report.sarif)
- JSON：[docs/examples/risky-report.json](docs/examples/risky-report.json)

## 限制

skillguard 是逐行靜態分析器：heuristic 規則產生的是**風險信號**而非定論；
跨行拼接的指令可能規避比對；編碼酬載只依形狀標記、絕不解碼。完整清單見
[docs/limitations.md](docs/limitations.md)。

## 授權

[MIT](LICENSE) © 2026 Yakitori197 (YoLab)
