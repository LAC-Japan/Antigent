# Agent harness（defender側）

Antigentのdefenderは**OpenCode**（`OPENCODE_VERSION`で固定、既定2.3.0）上で動きます。サポートし、
テストしているharnessはこれだけです。このページは、Antigentの他の部分がharnessに何を前提としているかを
制約として示します。別のharnessで動かす場合は、ここに沿って意図的に変更してください。

## harnessが満たすべき制約

defenderに使うharnessは、次のすべてを満たす必要があります。1と2はsecurity boundaryです。緩めないでください。

1. **操作手段はgatewayだけ。** Defense Gateway（`python3 /antigent/gateway/defense_gateway.py`）を
   stdioのlocal MCP serverとして登録し、containerの環境変数（`DOCKER_HOST`、`DEFENSE_LOG`、
   `ANTIGENT_SCENARIO`、`*_CONTAINER`）を引き渡します。
2. **それ以外のtoolはすべて禁止。** shell、fileの読み書き・検索・一覧、web fetch、web search、
   code search、LSP、task list、sub-agentを禁止し、gatewayのtoolとskillの読み込みだけを残します。
   これにより、agentはgatewayの型付き・監査付きの操作以外では、network、container、自身のfileに
   到達できません。
3. **1回の呼び出しで1ターン、非対話。** driverはpromptを引数として渡してharnessを起動し、終了を待って
   exit codeを読みます。端末からの入力を待ってはいけません。
4. **sessionの継続。** 次の呼び出しで前の会話を継続でき（OpenCodeでは`--continue`）、contextが
   伸びればharnessが圧縮（compaction）します。policyは、agentが自分の置いたdecoyを覚えていることを
   前提にしています。
5. **policyの読み込み。** 作業directory（`/antigent`）の`AGENTS.md`を指示として読み、
   `.opencode/skills/<name>/SKILL.md`（front matterは`name`、`description`）をskillとして見つけます。
   harnessが別のfileやfolderを読む場合は、linkかcopyで対応し、harnessのために内容を書き換えないでください。
6. **modelとnetworkの設定は環境から。** modelは呼び出しごとに指定でき（`ANTIGENT_MODEL`、OpenCodeでは
   `-m provider/model`）、containerの環境にあるproxyとCAの設定に従います。
7. **機械可読な出力（任意）。** `ANTIGENT_OPENCODE_JSON=1`（既定）のとき、driverは1行1 JSONのevent
   （`--format json`）を読み、ターンごとのLLM step数、token数、tool、時間を記録します。
   `ANTIGENT_OPENCODE_JSON=0`でもターンは動きますが、Consoleにprofileは表示されません。

## OpenCodeを前提にしている箇所

| 場所 | OpenCode固有の内容 |
|---|---|
| `gateway/driver.py` | `run_turn`がcommand（`OPENCODE_BIN run [--continue] [-m model] [--format json] <prompt>`）を組み立て、`parse_opencode_json`がOpenCodeのevent形式を読む |
| `opencode.free.jsonc`、`opencode.lab.jsonc` | 制約1と2：gatewayのMCP登録とtoolの禁止リスト |
| `antigent/Dockerfile` | 固定したOpenCode releaseのinstall |
| `AGENTS.md` | OpenCodeがsessionを圧縮すること、`.opencode/skills/`の場所。tool名はOpenCodeの形式（`antigent_observe_events`：MCP server名＋tool名）で、他のharnessでは名前が変わることがある |

## 別のharnessを使う場合

サポート対象外の構成です。行う場合は次に従ってください。

- 上の制約をすべて満たし、制約2はagentにshellの実行やfileの読み取りを依頼して確認します。modelが
  断るのではなく、harnessが拒否する必要があります。
- 変更するのは上の表の箇所だけにします。gateway、Scenario Adapter、skillはそのままにします。
- `AGENTS.md`やskillを変えると、各runに記録されるpolicy hash（`agent_start.run.policy`）が変わります。
  結果は同じhashのrun同士でしか比較できません。

attacker側はこのページの対象外です。Attack BoxのsampleもOpenCodeを使います
（[attackbox.md](attackbox.md)）。
