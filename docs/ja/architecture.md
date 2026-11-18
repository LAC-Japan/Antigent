# アーキテクチャ

Antigentは敵対的ラボの**defense plane**です。target環境を監視し、attackerの進行を
妨げるAI agentです。defense imageにはtargetもattackerも含まれません。別buildの
Attack Box sampleがoptional exampleとして提供されますが、defense containerおよび
そのtrust boundaryには含まれません。

**言語:** [English](../architecture.md) | 日本語

```
            your attacker (any agent / human)
                 |  commands over the target's exposed ports
                 v
   +-----------------------------+        Docker API (logs, diff, exec)
   |   your target containers    | <---------------------------+
   | (scenario adapter's roles)  |                             |
   +-----------------------------+                             |
                 ^   logs / fs changes                         |
                 |                                             |
   +-----------------------------+   runs/defense/*.jsonl   +--+----------------+
   | sensor daemon  (always-on)  | ------------------------> | Defense Gateway  |
   +-----------------------------+                           | (MCP server)     |
                 |  elevated events                          |  allow-list exec |
                 v                                           +--^-----------+--+
   +-----------------------------+                              | submit_turn |
   | driver (one turn per burst) | --- `opencode run` ------->  | OpenCode    |
   +-----------------------------+                              | (Antigent)  |
                                                                 +------------+
   +-----------------------------+
   | console (viewer + eval)     |  reads runs/ only, no Docker, no exec
   +-----------------------------+
```

## 観測と介入の境界（O1）

- Antigentが見るのは**defender側のtelemetryのみ**です。target containerのログと
  ファイルシステム変更（およびnetwork tap）です。attacker自身の
  command streamは決して読みません。
- attacker stream（`runs/attacker/attacker.jsonl`）は、観察者と評価のために存在します。
  読むのはConsoleと`eval/`だけです。`antigent` containerは`runs/defense/`のみを
  mountするため、この境界はファイルシステムレベルで維持されます。
- AntigentはDefense Gatewayを通じてのみtargetに作用します。Gatewayはscenarioが
  `exec_roles`として宣言したcontainerにだけ`docker exec`し、それ以外には実行しません
  （`antigent-*` container自体も拒否されます）。

## コンポーネント

| コンポーネント | 役割 |
| --- | --- |
| `gateway/sensor.py` | 常時稼働のcollector: containerログ、`docker diff`、network flow。`level`（`baseline` / `raw` / `elevated`）と`internal`タグ付きで`runs/defense/sensor.jsonl`に書き込みます。fresh stateではadapter宣言のclean calibrationを実行し、`sensor.baseline.json`とreadiness状態を永続化します。 |
| `gateway/baseline.py` | 汎用のrecurring-event学習と完全一致filter。duration、repetition policy、event kind、比較属性はScenario Adapterが所有します。学習済みeventは検出windowやdriver activityに供給されません。 |
| `gateway/driver.py` | elevated eventのburstごとに1回（debounce済み）、または通常activity継続中は定期的に、1回の`opencode run` turnを開始します。介入後の再観測はmodel turnを使わずdriver自身が紐付け、submitが受理された時点でturnを終了し、attack終了後に最終再観測turnを1回実行します。turnは`runs/defense/driver.jsonl`に記録されます。 |
| `gateway/defense_gateway.py` | 3つのtoolを持つMCP server: `describe_scenario`、`observe_events`、`submit_turn`。1 turnあたり最大1件の予約済みtyped operationをScenario Adapter経由で実行し、assessment / decision / actionを記録します。 |
| `gateway/intervention_gate.py` | fail-closedで永続的なtyped-action予約。1 observation turnあたり1 action、target / payload dedup、直列再観測を強制します。 |
| `gateway/netsensor.py` | network tap（常時起動）: Docker bridge上のHTTP requestとTCP接続を`runs/defense/net/flows.jsonl`にcaptureします。 |
| `server.py`、`static/`、`console/` | Console: `runs/`上のlive viewer。container内ではviewer専用です。 |
| `eval/metrics.py` | 1回のrunの要約（検知までの時間、介入、honeytokenの使用）: `python3 eval/metrics.py runs/demo` |
| `scenarios/<name>/` | Scenario Adapter: どのcontainerがroleか、どのsensorが監視するか、ログ行をどうevent化するか（`scenario.json`）、型付き操作とそのrole・対象field・agentに示す書式（`adapter.py`）、およびagent向けのscenario context（`context.md`）。core（gateway、driver、policy、skill）はこれらを名指ししません。contextに書くのは守る環境（構成、telemetry、使える操作）だけで、攻撃経路、環境の弱点、攻撃者の想定行動は書きません。 |
| `eval/` | stream merge、metrics、run比較、attacker-log検証。 |

## ポリシーとスキル

agentの振る舞いは`AGENTS.md`（loop: observe -> predict -> pre-empt -> submit once）と
`.opencode/skills/`（対応方針: artifact-path decoy、in-environment instruction、
共通deception rule、containment、observe-only）に定義されます。
Gatewayはrole allow-listと1 turnあたり1回のaccepted submitを強制します。
Typed protocolは永続的な予約とadapter仲介のnative operationを追加します。
Skill名からcapabilityを推測することはありません。defenderのharnessはOpenCodeです。Antigentが
harnessに前提としていることは[harness.md](harness.md)に制約として記載しています。

## Typed action・証跡・recovery

CI/CD Goat adapterは`gitea_repo_file`と`jenkins_disable_job`を実装しています。
Gitea file作成は正確なnative repository / ref / pathと、独立に読み戻したcommitを使います。
Jenkins containmentは正確なWorkflowJobとAPI readbackを使います。どちらもnative観測と
side-effect snapshotを記録し、process exit 0をtarget deliveryとはみなしません。

`runs/defense/intervention_state.json`はaction ID、payload / target hash、native観測ID、
再観測の紐付けを記録します。`runs/defense/defense.jsonl`はaccepted turnとnative delivery /
containment観測を記録します。attacker停止後、driverの最終再観測は
`driver.finalized.json`を書きます。続いてdemo runnerがadapterのrecoveryコマンドを呼び、
`recovery.json`を書きます。`stop`は不完全なrecoveryを再試行し、完了済みreportの重複実行は
避けます。競合・不完全なrecoveryは隠さず報告されます。recoveryの完了はcontainmentの
有効性を意味しないため、reportでは`containment_final[].status`を別に保持します。

## Run manifest

Gateway起動のたびに`agent_start`レコードが`runs/defense/defense.jsonl`に追加されます。
policy hash（AGENTS.md + skills）、model名、scenario名 / hash、mechanism versionを含むため、
exportされた任意のwindowは自己記述的です。秘密情報は記録されません。

## Trust boundary

- targetとdefense planeは1つのDocker daemonを共有します。`socket-proxy` containerが
  `docker.sock`の唯一の保持者（`apiguard/`のAPI guard）で、ps / inspect / logs / diffと宣言済みtargetへのexecのみを許可します。
- ConsoleはDockerアクセスもcommand実行のcodeも持ちません（表示専用）。
- attackerはtargetの公開port経由でのみ到達でき、Docker socketや`antigent-*` containerへの
  pathを持ってはいけません。
