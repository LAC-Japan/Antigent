# セキュリティモデル

Antigentは**ラボ用defense plane**です。target roleとして宣言したcontainer内で
commandを実行します。本番システムに向けては絶対に使用しないでください。

**言語:** [English](../security.md) | 日本語

## Antigentにできること

- 観測: target containerのログ、ファイルシステムdiff、hostのDocker bridge上のnetwork flow。
- 作用: Scenario Adapterが宣言した型付き操作だけを実行し、raw commandは拒否します。
  CI/CD Goatでは、Gitea repositoryへの新規file作成（`docker.sock`を保持する唯一の
  containerである`socket-proxy`経由で、Gitea containerへ`docker exec`）と、Jenkins jobの
  1件disable（Jenkins API）です。
- 復旧: CI/CD Goat adapterは最終containmentを検証し、nativeのbefore / after
  snapshotから自身のtyped変更をrestoreできます。recoveryは競合する後続の
  Gitea commitを上書きせず、不完全・未検証の結果は報告します。

## Antigentにできないこと

- attackerのcommand streamは読めません。`antigent` containerは`runs/defense/`のみを
  mountします。attackerログ（`runs/attacker/`）はConsoleと評価用であり、
  agentからは到達不能です。
- allow-list外では実行できません。Gatewayは対象roleが実行可能でないactionを拒否し、
  `antigent-*` container自体も拒否します。Typed protocolはさらに実行前の永続的予約を
  必須とし、重複operationを拒否し、再観測が完了するまで次の変更をblockします。
- 自身のshellを持ちません。OpenCode設定はdefense agentのshell / edit / web toolを
  拒否しており、capabilityは3つのgateway toolのみです。

## Defense planeの封じ込め

| コンポーネント | 権限 |
| --- | --- |
| `antigent`（container `antigent-core`） | Docker socketなし。`socket-proxy:2375`に到達。gateway code、scenario、policy、`runs/defense/`をmount |
| `socket-proxy`（container `antigent-socket-proxy`、API guard、`apiguard/`） | `docker.sock`を保持。`ps` / `inspect` / `logs` / `diff`と、宣言したtarget container（`GUARD_EXEC_CONTAINERS`）への`exec`のみ許可。create / start / kill / rm / cp / images / networks、privileged exec、privileged・Docker socket mount・`antigent-*` containerへのexecを拒否。host addressを持たないinternal network上で`antigent`からの接続のみ受理 |
| `console` | viewer専用。Dockerアクセスなし（guardのnetworkに不参加）、command実行・operator record受付なし。127.0.0.1:8765にbind。不正な`Host` header（DNS rebinding）とcross-site / 非JSONのPOST（CSRF）を拒否 |
| `netsensor` | `network_mode: host`、`cap_drop: ALL` + `NET_RAW`。Docker APIなし |

## LLM認証情報

- defense agentのmodel認証情報は`.env`（`.env.example`参照）から供給され、
  defense plane container内にのみ存在します。Bedrockを使う場合は
  `bedrock:InvokeModel*`にscopeしたIAM keyを使用してください。
- Consoleの`runs/` exportにはrun manifest（policy hash、model名、endpoint host）が
  含まれます。API keyは決して含まれません。

## Target認証情報とrun成果物

- `jenkins_disable_job`には`ANTIGENT_JENKINS_URL`、`ANTIGENT_JENKINS_ADMIN_USER`、
  `ANTIGENT_JENKINS_ADMIN_PASSWORD`が必要です。必要なtarget scopeのみを持つ
  ラボ専用の管理者認証情報を使用してください。他のtyped operationには
  この認証情報は不要です。
- `.env`と完了済みrun成果物は公開物に含めないでください。Typed turnログは
  raw model textとtool payloadを省略しますが、防御証跡には意図的にmarkerと
  target-nativeの結果レコードが含まれるため、共有前に必ずレビューしてください。

## Attacker側（接続する場合）

- attackerはtargetの公開port経由でのみ到達します。Docker socket、
  `antigent-*` container、defense networkには決して到達させません。
- attackerは`runs/attacker/`のみに書き込みます。

## Console

Consoleは表示専用で、command実行のcodeを持ちません。旧operator mode（attacker / defender
のcommand入力、commandのhold、operator record）は削除済みです。唯一の状態変更requestである**New session**は、不正な`Host` header（DNS rebinding）
とcross-site / 非JSONのPOSTを拒否します。

## 報告

このパッケージは研究・訓練用に公開されています。脆弱性はリポジトリのsecurity
policyまたは配布元が指定する窓口から報告してください。認証情報、非公開証明書、
target flag、機密のrun成果物は含めないでください。

## 既知の制約（隔離ラボ前提）

- Attack Box sampleはattackboxを`antigent-attack-lab`（`internal` + `inhibit_ipv4`）にのみ
  参加させ、LLM APIへは`egress-proxy`（allowlistのHTTPS `CONNECT`のみ）経由で到達させます。
  `live_demo.py run`はbox内から境界をprobeし、1つでも通れば攻撃を開始しません。
- Attack Boxに渡すcredentialはattacker agentから読めます。attacker専用の低上限keyのみを渡し、
  defenderのkeyは渡しません。
- `attacker.jsonl`が指す出力fileは、区切り文字や`..`を含まない名前のみ、symlinkを辿らずに読みます。
- attackerのcommand記録はattacker権限のshell hookが書くため、協調的なagentに対するground truth
  であり、改ざん耐性のある監査ログではありません。
- attackerが制御するtextはtarget telemetry経由でdefense modelに届きます。raw commandを拒否する
  typed protocolを推奨します。
- `antigent` container自体はmodel API用に通常のegressを持ちます（agentにshell / web toolはありません）。
- `netsensor`はhost networkとDocker bridgeのpromiscuous captureを使います。

