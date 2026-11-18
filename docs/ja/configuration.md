# 環境に合わせた設定

**言語:** [English](../configuration.md) | 日本語

IPアドレスやportは環境ごとに異なります。Antigentはそれらを一切ハードコードしません。
Dockerが知っているものは実行時に取得し、利用者にしか分からないものだけを`.env`で設定します。

## 実行時に自動取得するもの（設定不要）

| 対象 | 方法 |
|---|---|
| target containerのIP | API guard経由でscenarioのroleを`docker inspect` |
| flowとtargetの対応 | netsensorの宛先IP → role。targetが別networkに参加したら再構築 |
| targetのservice port | 使いません。attackerはlab network上でcontainer自身のportへ到達し、hostに公開したportは関係しません |
| LinuxでのDocker hostのaddress | target networkのgateway（internal扱い） |
| Consoleのtarget health | sensorが取得したcontainer状態（`running` / `healthy`）。Consoleはtargetへ接続しません |
| Attack BoxとAPI guardのnetwork | Composeが固定subnetなしで作成（Dockerのaddress poolから割当） |

## 必要に応じて`.env`で設定するもの

| 変数 | 既定値 | 変更する場面 |
|---|---|---|
| `CONSOLE_PORT` | `8765` | portが使用中 |
| `CONSOLE_BIND` | `127.0.0.1` | 別のマシンからConsoleを見る（SSH tunnelを推奨。公開するとrun logが見える） |
| `CONSOLE_ALLOWED_HOSTS` | 空 | browserに入力するhost名/IPが`127.0.0.1` / `localhost`以外 |
| `DEMO_RUN_ID` | `demo` | runを分けたい（同じIDの前回runは自動で退避） |
| `GITEA_CONTAINER`、`JENKINS_CONTAINER`、`PROD_CONTAINER` | CI/CD Goatの名前 | labのcontainer名が違う |
| `ANTIGENT_HOST_ADDRESSES` | 空 | Docker Desktopで、このマシンのbrowserからlabを操作し、それをclientとして見せたくない（VMのhost address。多くは`192.168.65.1`）。Antigent自身のJenkins requestは登録不要：run毎の乱数`antigent_self` mark（`ANTIGENT_SELF_MARK`、`live_demo.py`が設定）を付けて送り、その送信元はinternalとして扱われる |
| `NET_IFACES` | `^(docker0|br-.*)$` | Docker bridgeのinterface名が異なる |
| `ATTACKER_EGRESS_EXTRA_ALLOW` | 空 | OpenCodeが別のAPI hostを必要とする |
| `ATTACKER_EGRESS_UPSTREAM_PROXY` | 空 | Internetへ出るのにHTTP proxyが必要 |
| `ca/combined-ca-bundle.pem`（file） | なし | TLS検査proxyの配下（`ca/README_JA.md`参照） |

環境に依存しない固定値: `socket-proxy:2375`と`egress-proxy:3128`はDockerの内部network上の
名前とportで、hostや他のマシンからは見えません。

Dockerの既定address poolが社内やVPNの範囲と衝突する場合は、Docker daemon設定の
`default-address-pools`を変更してください。AntigentはDockerが割り当てたaddressをそのまま使います。
