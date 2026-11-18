# Attack Box sample

このsampleは、**明示的に承認された隔離ラボ**で使う、target非依存のAI / 人間 attacker planeです。
非特権shell、OpenCode、一般的なnetwork client、version固定のsecret scanner、JSONL command
loggingを提供します。target application、課題攻略、defense telemetry、非公開実験部品は
含みません。

**言語:** [English](../../examples/attacker/README.md) | 日本語

## 境界と既定値

- `docker compose exec`を使用し、SSH server、password login、公開portは設定しません。
- `AUTHORIZED_TARGETS`は空です。設定されるまで、付属agent roleはscopeを確認して停止します。
- **egressはpromptではなくDockerで強制します。** attackboxは`antigent-attack-lab`
  （`internal` + `com.docker.network.bridge.inhibit_ipv4`）にのみ参加します。default route、
  外部DNS、Docker hostのどのaddressにも到達できません（`internal`単体ではhostのbridge
  addressに到達できます）。外への唯一の経路は`egress-proxy`で、`ATTACKER_EGRESS_ALLOW`
  （LLM API）へのHTTPS `CONNECT`のみを許可し、web検索、平文HTTP、他host / port、IP直指定、
  private / metadata addressへ解決される名前を拒否します。判定は`runs/egress/egress.jsonl`に記録します。
  tunnelは開いた時点で`allow`、閉じた時点で`close`として記録されます。OpenCodeのmodel catalog
  （`models.opencode.ai`）は許可していないため、`OPENCODE_DISABLE_MODELS_FETCH=1`で取得自体を止め、
  pin したreleaseに同梱されたcatalogを使います。
- 到達できるのは明示的に接続したtargetだけです:
  `docker network connect antigent-attack-lab <target-container>`
- `.env`のmodel credentialはagentが実行する全commandから読めます。attacker専用の
  低上限keyを使い、defenderのkeyは渡さないでください。
- Docker socket、host gateway、defense networkへの接続はありません。
- `no-new-privileges`を設定し、agent commandは非特権`attacker`で実行します。
- 標準のpublic CA rootsで動作し、TLS検証を無効化しません。

## 設定と起動

target labを起動してから、配布物の`examples/attacker/`へ移動します。

```sh
cd examples/attacker
cp .env.example .env
```

`.env`で次を設定します。

1. `ATTACKER_EGRESS_ALLOW`: model APIのhost（既定`opencode.ai`）
2. `AUTHORIZED_TARGETS`: 明示的に承認されたhostまたはURLのcomma区切りlist
3. 必要ならmodel endpointとcredential（`.env`は共有・公開しない）

到達可能であることは承認の代替になりません。network rangeへの拡大や、defense / Docker hostへの
接続は行わないでください。

```sh
docker compose up -d --build
docker network connect antigent-attack-lab <target-container>
docker compose exec -it --user attacker attackbox opencode
```

`docker compose down`の前にtargetを切り離します
（`docker network disconnect antigent-attack-lab <target-container>`）。

既定の`opencode.free.jsonc`では`/models`でmodelを選びます。独立したOpenAI-compatible
endpointを使う場合は`.env`で次を設定します。

```dotenv
ATTACKER_OPENCODE_CONFIG=opencode.lab.jsonc
ATTACKER_LLM_BASE_URL=https://llm.lab.invalid/v1
ATTACKER_LLM_API_KEY=replace-locally
ATTACKER_LLM_MODEL_ID=your-lab-model
```

OpenCodeのweb toolは拒否されています。shellは使えますが、`AGENTS.md`のscopeとtarget
allow-listが適用されます。

## Shellとcommand ground truth

```sh
docker compose exec --user attacker attackbox bash -c 'printf "hello\n"'
docker compose exec -it --user attacker attackbox bash
```

`BASH_ENV`、`/etc/bash.bashrc`、`/etc/profile.d/`が`cmdlog.sh`を読み込みます。OpenCodeの
Bash toolと`bash -c`は同じcommand IDを持つ`start` / `end` recordを出力します。対話Bashは
command完了後に`cmd` recordを出力します。stdout / stderrは呼び出し側にもそのまま渡します。

対象はtop-levelの`bash -c`と対話Bashです。直接実行された非Bash programやscript内部の子shellは
このhookの記録対象外で、二重記録を防ぐため入れ子Bashは抑制します。これは対応するOpenCode /
exec経路のoperational ground truthであり、改ざん不能なaudit logではありません。

## JSONL contract

container内の`/var/log/attackbox/attacker.jsonl`が、配布rootの
`runs/attacker/attacker.jsonl`へmountされます。

| Field | 内容 |
| --- | --- |
| `ts` | 小数を含むUnix時間（秒） |
| `event` | `start`、`end`、または完了した対話`cmd` |
| `id` | command ID。同じcommandの`start` / `end`で共通 |
| `command` | `start` / `cmd`のcommand本文 |
| `exit_code` | `end` / `cmd`の整数status |
| `via` | 到達経路。通常は`exec` |
| `user`, `cwd` | shell identityとworking directory |

`bash -c`では、必要に応じて`out/<id>.out`と`out/<id>.err`も記録します。mountされるのは
`runs/attacker/`だけで、他のrunやdefense directoryは見えません。

## 任意のcombined CA bundle

TLS検査proxyがある環境では、public rootsと追加の信頼rootを含むPEM bundleを使用します。

1. `examples/attacker/combined-ca-bundle.pem`へ配置します。
2. `examples/attacker/docker-compose.yml`の該当するread-only volumeを有効化します。
3. `.env`に`CA_BUNDLE_PATH=/etc/attackbox/ca/combined-ca-bundle.pem`を設定します。
4. containerを再作成します。選択したbundleが読めなければ起動に失敗します。

CA pathはcurl、Git、Python requests、OpenSSL系tool、Nodeへ一貫して渡されます。image buildは
既定でpublic rootsを使います。OpenCodeとscannerのdownload時に追加rootが必要な場合は、
`combined-ca-bundle.pem`を別のlocal directoryへ置き、そのdirectoryを`ATTACKER_CA_CONTEXT`に
設定します。build時の検証downloadにだけmountされます。証明書検査を回避してbuildやcommandを
成功させないでください。

## 第三者toolとlicense

OpenCode、Gitleaks、TruffleHogのversionはbuild argumentで固定しています。build時に公式
配布物を取得し、第三者source / binary / imageをsource ZIPへ同梱しません。取得したtoolには
それぞれのupstream licenseが適用されます。自作sample fileはApache License 2.0です。
