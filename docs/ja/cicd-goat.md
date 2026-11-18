# CI/CD Goat targetとの接続

同梱のScenario Adapter（`scenarios/cicd-goat/`）は、
[CI/CD Goat](https://github.com/cider-security-research/cicd-goat) training環境を記述します。
課題そのものの手順はupstream文書を参照してください。

**言語:** [English](../cicd-goat.md) | 日本語

CI/CD Goat本体、source、第三者container imageはAntigent配布物に含めていません。承認された
ラボで別途取得・起動し、upstreamのlicenseとnoticeに従ってください。同梱しているのは
Antigent自作のadapterだけです。

## 観測role

| Role | Container | Sensorが読む情報 |
| --- | --- | --- |
| `gitea` | `gitea` | HTTP access log（認証失敗、client別request）、filesystem変更 |
| `jenkins` | `jenkins-server` | build log、filesystem変更 |
| `prod` | `prod` | filesystem変更（tamper検出） |

CTFd、GitLab、localstackなどはattack対象として到達できても、既定ではlog経由の観測対象外です。
`netsensor`により、これらのnetwork flowも表示されます。

## 必要条件

- CI/CD GoatとDefense Planeが同じDocker daemon上で動作すること
- 既定port: Gitea 3000、Jenkins 8080、CTFd 8000、prod 8008 / SSH 2222
- 観測とGitea file操作はDocker APIを使用すること（API guardが`exec`を許可するのはGitea containerだけ）
- Jenkins WorkflowJob containmentには、別途Jenkins管理者credentialが必要。`.env`の`JENKINS_URL` /
  `JENKINS_ADMIN_USER` / `JENKINS_ADMIN_PASSWORD`で設定し、local `.env`にだけ置くこと

`scenarios/cicd-goat/scenario.json`は、roleとcontainer名、log rule、driverを起動するelevated
event、target内部通信の扱いを定義します。`request_rules`は外部clientのrequestを独自のevent kindとして
報告します（ここではrepositoryのclone/fetch・file読み取りを`repo-read`）。sensorの`surface`は内部扱いの
logのうち表示する行を指定します（ここではJenkinsのpull request buildを`pipeline-run`）。`baseline` blockは、attacker-freeの60秒観測、
20秒以上の期間に2回以上同じ通信が現れるという反復条件、access log / network telemetryで
完全一致させる属性を宣言します。Gitea `/user/events`やCTFd `/health`のような定期pollingを
学習しますが、client IP全体、認証失敗、filesystem変更、未学習pathは除外しません。
attacker開始前に`baseline.ready`を確認してください。このadapterは個別課題ではなくCI/CD Goat
環境に対応付けます。repository・credential・flag・攻撃目的が異なっても、同じserviceと
telemetryを使う課題ではadapterを共用し、それだけを理由に複製しません。container名が異なる
場合はscenario directoryをコピーして調整するか、対応する`*_CONTAINER`環境変数を設定します。

## 起動

配布rootで`.env`を設定し、`uv run python live_demo.py run`を実行します（手順は
[usage.md](usage.md)）。targetを取得する手順はupstreamの現在の文書に従い、licenseを確認してください。

## 型付きaction

adapterが受け付けるのは次の操作だけです（raw shell commandは不可）。

| Operation | 対象 | Native確認と復旧 |
| --- | --- | --- |
| `gitea_repo_file` | 正確なrepository / refに未存在のfileを1件作成 | commitを独立にreadbackし、後続の競合commitを上書きせずrecovery |
| `jenkins_disable_job` | 正確なWorkflowJobを1件disable | APIで状態をreadbackし、最終build状態の確認と有効時の再有効化 |

gatewayは、1観測turnにつき1 action、実行前reservation、対象の重複拒否、次の変更前の
read-only再観測を強制します。試行回数に固定の上限はありません。exit 0、targetへのdelivery /
containment、攻撃者のread / follow、再観測は別の証拠段階です。

## 典型的な表示

1. 攻撃者がGiteaを列挙すると`new-source`や`recon-burst`が記録されます。
2. driverがturnを開始し、Antigentが次の行動を予測してdecoyなどを選択します。
3. 攻撃者がdecoyを使うとConsoleがhoneytoken使用を表示し、defense logにdelivery、read / follow、
   再観測の証拠を区別して記録します。
4. Antigentが使えるのは上記2操作だけです。

これらは動作の説明であり、すべてのrunで同じ結果になることを保証する性能主張ではありません。

## 制限

- 単一Docker hostのみ
- netsensorは平文HTTPだけを内容表示し、HTTPS/SSHは接続記録のみ
- TCP再構成は行わない
- Docker外のVMにはremote sensorが必要で、このadapterの対象外
