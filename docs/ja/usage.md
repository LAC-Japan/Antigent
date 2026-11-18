# Antigent Defense Plane - 使い方ガイド

このガイドでは、CI/CD Goat Caterpillarデモの完全なセットアップ、実行、
結果確認の手順を説明します。

**言語:** [English](../usage.md) | 日本語

---

## 目次

1. [前提条件](#前提条件)
2. [環境構築](#環境構築)
3. [デモの実行](#デモの実行)
4. [結果の確認](#結果の確認)
5. [トラブルシューティング](#トラブルシューティング)
6. [詳細設定](#詳細設定)

---

## 前提条件

### システム要件

- **OS**: macOS、Linux、またはWSL2上のWindows
- **RAM**: 8 GB以上（16 GB推奨）
- **ディスク**: 10 GBの空き容量
- **Docker**: Docker Desktop 4.x以降、またはDocker Engine 20.10以降（Compose plugin含む）

### 必要なソフトウェア

1. **Docker（Compose含む）**

   インストール確認:
   ```sh
   docker --version
   docker compose version
   ```

2. **uvパッケージマネージャー**（推奨）またはPython 3.10以降

   uvのインストール:
   ```sh
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

3. **CI/CD Goat**（対象アプリケーション）

   ```sh
   git clone https://github.com/cider-security-research/cicd-goat.git
   ```

### Model要件

デモは既定でOpenCodeのfree modelを使用します（API key不要）。次も使用できます:

- **OpenAI model**（`openai/*`、roleごとのAPI key）
- **Amazon Bedrock model**（`amazon-bedrock/*`、roleごとのcredential）

> **データ利用に関する注意**: `opencode/*` modelを使う場合、promptとtool出力
> （challenge flag等のlab内secretを含む）はOpenCodeのmodel providerへ送信されます。
> 既定の`opencode/glm-5.3-flash-free`はzero-retention・学習不使用のpolicyですが、
> 他のfree modelの中にはデータを保持したりmodel改善に利用したりするものがあります。
> model選択前に <https://opencode.ai/docs/zen/#privacy> を確認し、実システムや
> 実credentialに対してデモを実行しないでください。
>
> **利用枠に関する注意**: OpenCodeのfree modelには1日の無料利用枠があります。
> 1回のデモ実行（5分間の自律攻撃＋防御turn）で枠を使い切ることがあり、その後は
> quotaがリセットされるまでmodel呼び出しがHTTP 429で失敗します。防御が応答しなく
> なったり攻撃が直ちに停止したりする場合は、リセットを待つか、`.env`の
> `ATTACKER_MODEL` / `DEFENDER_MODEL`を有償・provider key利用のmodelに切り替えて
> ください。

---

## 環境構築

### ステップ1: 配布物の展開

```sh
unzip antigent-<version>.zip
cd antigent-<version>
```

### ステップ2: 環境設定

example環境ファイルをコピー:

```sh
cp .env.example .env
```

`.env`を編集して設定:

```sh
# 必須: CI/CD Goat checkoutへのパス
CICD_GOAT_DIR=/path/to/cicd-goat

# Model選択（オプション、既定値を表示）
ATTACKER_MODEL=opencode/glm-5.3-flash-free
DEFENDER_MODEL=opencode/glm-5.3-flash-free

# Console port（オプション、既定: 8765）
CONSOLE_PORT=8765

# Attack timeout秒数（オプション、既定: 1800 = 30分）
ATTACK_TIMEOUT=1800
```

### ステップ3: 設定検証

container起動やmodel呼出しなしでdry-runを実行:

```sh
uv run python live_demo.py dry-run
```

期待される出力:
```
=== Antigent Demo dry-run ===
Run ID: demo
Defense plane: /path/to/antigent
CI/CD Goat: /path/to/cicd-goat

Configuration valid:
  Attacker model: opencode/glm-5.3-flash-free
  Defender model: opencode/glm-5.3-flash-free
  Console port: 8765
  Attack timeout: 1800s

dry-run complete. No containers, volumes, or model calls made.
Run 'uv run python live_demo.py run' to start the demo.
```

---

## デモの実行

### デモ開始

```sh
uv run python live_demo.py run
```

デモの実行内容:

1. **Fresh CI/CD Goat Caterpillar起動**（約60秒）
2. **Defense Planeのbuildと起動**（約120秒）
3. **Defense baselineの待機**（約60秒）
4. **AUTO攻撃者の開始**（約30秒）
5. **timeoutまたは完了まで監視**

### 期待される出力

```
=== Antigent Demo run (demo) ===

[1/5] Starting fresh CI/CD Goat Caterpillar...
  Target started: gitea, jenkins-server, prod

[2/5] Starting Defense Plane...
  Defense ready, Console at http://127.0.0.1:8765
  Jenkins containment ready (logged in as admin, administrator)
  （JENKINS_*が未設定なら "NOTE: Jenkins containment is off ..."、ログインや権限に問題があれば理由付きの WARNING）

[3/5] Waiting for defense baseline...
  Baseline observation complete

[4/5] Starting AUTO attacker...
  Egress check passed: only the allow-listed LLM API is reachable
  Attacker running (timeout: 1800s)

[5/5] Monitoring attack...
  Console: http://127.0.0.1:8765
  Press Ctrl-C to stop early

  attacker commands: 12 | LLM tunnels: 2 opened (2 open), 0 refused
  ...

Attack timeout reached
  attacker commands: 85 | LLM tunnels: 2 opened (2 open), 0 refused

Draining defense and final reobservation...
  Final reobservation accepted; recovery complete (2 effects)
  # typed actionによるtarget変更がなかった場合:
  # Final reobservation accepted; no target recovery required

Demo run complete. Console remains at http://127.0.0.1:8765
Run 'uv run python live_demo.py stop' to clean up.
```

### デモ停止

```sh
uv run python live_demo.py stop
```

正常終了するrunでは、完了を報告する前に最終再観測とtarget-native recoveryを実行します。
`stop`は必要なrecoveryをdefense plane停止前に再試行し、完了済みのrecovery reportがあれば
重複実行を避けます。復元または最終containment検証が不完全な場合は警告を表示します。
`runs/demo/defense/driver.finalized.json`と`runs/demo/defense/recovery.json`を確認してください。
recoveryの完了とcontainmentの有効性は別の評価です。`complete: true`だけをcontainmentが
最後まで有効だった証拠とみなさず、`containment_final[].status`も確認してください。

---

## 結果の確認

### Consoleへのアクセス

ブラウザで<http://127.0.0.1:8765>を開きます。

### Consoleレイアウト

Consoleは3つのpaneで構成:

| Pane | 内容 |
|------|------|
| **左** | Attack Boxのlogから取得した攻撃者command（評価用の正解データ。Antigentには見せない） |
| **中央** | 防御者が観測できるtelemetry（ログ、ファイル変更、ネットワークイベント） |
| **右** | Antigentのassessment、decision、action結果 |

### 防御成功の主要指標

1. **Defender viewのバナー**（固定表示、折り畳まれない）:
   - `✓ HONEYTOKEN TRIGGERED · attacker used decoy <marker>` — attackerが設置したdecoyを使った。
   - `⛔ CONTAINMENT VERIFIED · ...` — containmentが独立したreadbackで確認された。
2. **介入**（右pane）: `Decoy planted`カードと、`exit 0`とnative receiptを持つgateway action。
3. **攻撃者の行動**（左pane）: decoyの値を使うcommand、containment後に通らなくなった試行。

各介入は、別々の証拠段階として記録されます:
`delivered → read → followed / decision changed → reobserved`。

### 結果のエクスポート

Consoleの**Export**で`<session>-merged.jsonl`をダウンロードします。全plane（attacker
command、defender telemetry、Antigent turn、record、action、receipt）を時刻順に、1行1 JSONで
まとめたものです。

### 終了したrunの見直し

exportしたファイルは、Docker・lab・modelなしで後から開き直せます:

```sh
uv run python live_demo.py view ~/Downloads/<session>-merged.jsonl
```

<http://127.0.0.1:8766>を開くと、3つのpane、バナー、turn markerがファイルから再構成されます。
**Export**は同じファイルを返します。別のportは`--port`で指定します。必要なのはPython標準
libraryだけです（`python3 server.py --import <file> --port 8766`でも動きます）。

### 手動確認

結果を手動で確認することもできます:

```sh
# 防御ログの確認
cat runs/demo/defense/defense.jsonl | jq .

# 攻撃者ログの確認（利用可能な場合）
cat runs/demo/attacker/attacker.jsonl | jq .

# 残っているcontainerがないことを確認
docker ps | grep -E "(antigent|gitea|jenkins|prod)"
```

---

## トラブルシューティング

### よくある問題

#### 1. Docker daemonが起動していない

**エラー**: `Docker daemon not running or not accessible`

**解決策**: Docker DesktopまたはDocker daemonを起動:
```sh
# macOS
open /Applications/Docker.app

# Linux
sudo systemctl start docker
```

#### 2. CI/CD Goatが見つからない

**エラー**: `CICD_GOAT_DIR not found: /path/to/cicd-goat`

**解決策**: CI/CD Goatをcloneするか、`.env`のパスを更新:
```sh
git clone https://github.com/cider-security-research/cicd-goat.git
# .envのCICD_GOAT_DIRを実際のパスに更新
```

#### 3. Portが既に使用されている

**エラー**: `port is already allocated`など

**解決策**: `.env`でconsole portを変更:
```sh
CONSOLE_PORT=8766
```

#### 4. Modelが利用できない

**エラー**: Model APIエラーやタイムアウト

**解決策**:
- `opencode models`でmodel名を確認
- OpenAI modelの場合、API keyの有効性を確認
- 別のfree modelを試す（例: `opencode/deepseek-v4.1-flash-free`）

#### 5. Defense baselineのタイムアウト

**エラー**: Defenseが`baseline.ready: true`に到達しない

**解決策**:
- target containerが完全に起動していることを確認
- targetログを確認: `docker logs gitea`、`docker logs jenkins-server`
- 必要に応じて`ANTIGENT_WARMUP_TIMEOUT`を増加

### リセット

完全にリセットする必要がある場合:

```sh
# すべて停止
uv run python live_demo.py stop

# containerとvolumeを削除
docker compose down -v
cd /path/to/cicd-goat && docker compose down -v

# runデータを削除
rm -rf runs/demo

# 最初からやり直し
uv run python live_demo.py run
```

---

## 詳細設定

### OpenAI Modelの使用

より良い攻撃・防御性能のためにOpenAI GPT-4を使用:

```sh
# .envで
ATTACKER_MODEL=openai/gpt-4o
DEFENDER_MODEL=openai/gpt-4o
OPENAI_ATTACKER_KEY=sk-your-attack-key
OPENAI_DEFENDER_KEY=sk-your-defense-key
```

### Amazon Bedrockの使用

```sh
# .envで
ATTACKER_MODEL=amazon-bedrock/global.moonshotai.kimi-k3
DEFENDER_MODEL=amazon-bedrock/global.moonshotai.kimi-k3
ANTIGENT_AWS_REGION=us-east-1                 # 両roleで使用
ANTIGENT_AWS_BEARER_TOKEN_BEDROCK=...         # defender（またはANTIGENT_AWS_ACCESS_KEY_ID / _SECRET_ACCESS_KEY）
ATTACKER_AWS_BEARER_TOKEN_BEDROCK=...         # attacker専用credential（またはATTACKER_AWS_ACCESS_KEY_ID / ...）
```

attackerのcredentialは、attackerが実行するすべてのcommandから読めます。attacker専用の、短期・
低上限のものを使ってください。defenderのcredentialの再利用は、
`ATTACKER_SHARE_DEFENDER_CREDENTIALS=1`を設定しない限り拒否されます。

### Jenkins封じ込め

Jenkinsジョブ封じ込め（`jenkins_disable_job`）を有効にするには、labのJenkins管理者のcredentialを
指定します。使うのはadapterだけで、agentにはそれを読めるtoolがありません:

```sh
# .envで
JENKINS_URL=http://host.docker.internal:8080
JENKINS_ADMIN_USER=<labのJenkins管理者>
JENKINS_ADMIN_PASSWORD=<そのpassword>
```

credentialなしの場合、Gitea decoy介入のみ利用可能です。

### カスタムRun ID

上書きせずに複数のデモを実行する場合:

```sh
# .envで
DEMO_RUN_ID=my-test-run
```

結果は`runs/my-test-run/`に保存されます。

### Attack Timeout

最大攻撃時間を調整:

```sh
# .envで（既定: 1800 = 30分）
ATTACK_TIMEOUT=3600  # 60分
```

---

## セキュリティノート

1. **承認**: 承認されたシステムでのみAntigentを使用してください。
2. **本番環境**: 本番環境には絶対に向けないでください。
3. **Credential**: API keyは`.env`に保管し、バージョン管理にはコミットしないでください。
4. **Network**: attack boxはLLM proxyへの外部ネットワークアクセスのみ可能です。
5. **Isolation**: すべてのcontainerは外部への公開なしで単一Dockerホスト上で実行されます。

---

## 次のステップ

- **Scenario adapter**: `docs/ja/cicd-goat.md`を参照
- **runの要約**: `python3 eval/metrics.py runs/demo`（検知までの時間、介入、honeytokenの使用。標準libraryのみ）
- **アーキテクチャ**: `docs/ja/architecture.md`でシステム設計を参照
- **セキュリティモデル**: `docs/ja/security.md`で詳細なセキュリティ境界を参照

---

## License

Apache License 2.0。[LICENSE](../../LICENSE)と[NOTICE](../../NOTICE)を参照してください。
