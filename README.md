# litellm-vuln-scanner

LiteLLM サプライチェーン攻撃 (v1.82.7 / v1.82.8) の影響調査を自動化するツール。
GitHub リポジトリおよびローカル開発環境を対象に、脆弱なバージョンの使用有無を検出する。

## 背景

2026年3月、PyPI で配布された LiteLLM v1.82.7 および v1.82.8 に悪意あるコードが混入された。
このマルウェアは SSH 鍵、クラウド認証情報、.env ファイル等を窃取し、バックドアを設置する。
詳細: https://github.com/BerriAI/litellm/issues/24518

## 必要なもの

- [uv](https://docs.astral.sh/uv/) (Python パッケージマネージャ)
- [GitHub CLI (`gh`)](https://cli.github.com/) （GitHub スキャン時のみ必要）

外部 Python パッケージは不要。標準ライブラリのみで動作する。

### uv のインストール

Mac:
```bash
brew install uv
```

Linux:
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

### gh のインストールと認証

Mac:
```bash
brew install gh
gh auth login
```

Linux (Debian/Ubuntu):
```bash
(type -p wget >/dev/null || sudo apt-get install wget -y) \
  && sudo mkdir -p -m 755 /etc/apt/keyrings \
  && out=$(mktemp) && wget -nv -O$out https://cli.github.com/packages/githubcli-archive-keyring.gpg \
  && cat $out | sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null \
  && sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
  && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null \
  && sudo apt update \
  && sudo apt install gh -y
gh auth login
```

## インストール

```bash
# グローバルにインストール（どこからでも litellm-vuln-scanner コマンドが使える）
uv tool install /path/to/litellm_vuln_scanner

# または GitHub から直接
uv tool install git+https://github.com/aRaikoFunakami/litellm-vuln-scanner
```

開発時はリポジトリ内で `uv sync` してから `uv run litellm-vuln-scanner` でも実行可能。

## 使い方

```bash
# GitHub: 認証ユーザーがアクセス可能な全リポジトリをスキャン（個人 + Organization）
litellm-vuln-scanner

# 特定ユーザーのリポジトリのみ
litellm-vuln-scanner --user aRaikoFunakami

# Organization のリポジトリのみ
litellm-vuln-scanner --org access-company

# 特定リポジトリを直接指定
litellm-vuln-scanner --repos myorg/repo1,myorg/repo2

# ローカル: 指定ディレクトリ配下をスキャン
litellm-vuln-scanner --local ~/GitHub

# GitHub + ローカル同時スキャン
litellm-vuln-scanner --org myorg --local ~/projects

# 出力先を指定（デフォルトは logs/YYYYMMDD_HHMMSS_TZ_label/ に自動生成）
litellm-vuln-scanner --local ~/GitHub --output-dir ./my_results
```

## 出力ファイル

1つのディレクトリに以下がフラットに出力される。

| ファイル | 内容 |
|---------|------|
| `litellm_scan_report.md` | 調査レポート（概要・結果・調査方法） |
| `litellm_scan_results.csv` | 検出結果（点検管理シート貼付用） |
| `litellm_scan_results.json` | 検出結果（プログラム処理用） |
| `*.log` | タイムスタンプ付き調査ログ（エビデンス） |

## 検出対象

直接依存:
- `litellm`

間接依存（litellm を内部的に利用するパッケージ）:
- `openhands`, `dspy`, `agentops`, `langfuse`, `mlflow`

スキャン対象ファイル:
- `requirements*.txt`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`
- `poetry.lock`, `setup.py`, `setup.cfg`, `Dockerfile`

ローカルスキャン時は上記に加え、システム Python および検出した仮想環境 (.venv) の
`pip freeze` から実際にインストールされたバージョンも確認する。

## 判定基準

| 判定 | 意味 |
|------|------|
| VULNERABLE | litellm 1.82.7 または 1.82.8 を使用 |
| SAFE | litellm を使用しているが安全なバージョン |
| WARNING | litellm をバージョン未指定で使用 |
| CHECK_INDIRECT | 間接依存パッケージを検出（要手動確認） |

## 安全性

GitHub スキャンは `gh` CLI 経由の GET リクエストのみで動作する。
コード内のバリデーション (`github_client.py`) により以下が強制される:

- 許可されたサブコマンド: `api`, `auth` のみ
- HTTP メソッド変更フラグ (`-X`, `--method`) の使用禁止
- API パスは `/user`, `/repos/`, `/search/` プレフィックスのみ許可

リポジトリへの書き込み・変更は一切行わない。

## ファイル構成

```
pyproject.toml
src/litellm_vuln_scanner/
  scanner.py           -- エントリポイント
  github_client.py     -- GitHub API クライアント (gh CLI 経由)
  local_scanner.py     -- ローカルディレクトリスキャン
  dependency_parser.py -- 依存ファイルのパース・判定ロジック
  reporter.py          -- CSV/JSON/Markdown/コンソール出力
```
