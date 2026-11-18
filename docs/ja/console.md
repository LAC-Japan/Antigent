# Console replayとデモ確認

Consoleは、target、attacker、defenderを起動せずに、完了済みrunのlayoutを再生できます。
Consoleは表示専用でcommand実行のendpointを持ちません。containerにはDocker socketもありません。

**言語:** [English](../console.md) | 日本語

## 同梱の合成デモ

配布物の展開rootで次を実行します。

```sh
mkdir -p runs
cp -R fixtures/sample-run runs/demo
python server.py --replay --run-dir runs/demo \
  --sensor-log '' --driver-log '' --port 8766
```

<http://127.0.0.1:8766>を開きます。`--replay`は既存JSONLを先頭から読みます。指定しない
場合は、従来どおりlive tailします。`--run-dir`は表示、reset、exportに使う
runs layoutを選択します。空のsensor/driver引数は、この小さなfixtureに存在しないstreamを
無効化します。

合成データであり、計測した性能結果として提示してはいけません。

## container版Consoleでのreplay

1. host上でfixtureを`./runs/demo`へコピーします。
2. `.env`へ次を追加します。

   ```dotenv
   ANTIGENT_RUN_DIR=/console/runs/demo
   ANTIGENT_REPLAY=1
   CONSOLE_PORT=8766
   ```

3. Consoleだけを起動します。

   ```sh
   docker compose up -d console
   ```

live modeへ戻るときはreplay設定を外してConsoleを再作成します。完了runのreplayと、実行中の
実験の`runs/`は分けてください。

## 完了runのlayout

```text
<run-dir>/
  attacker/attacker.jsonl   # 任意の表示・評価stream
  defense/defense.jsonl     # assessment、decision、action、observed event
  defense/sensor.jsonl      # 任意の連続sensor stream
  defense/driver.jsonl      # 任意のturn trigger/end stream
  defense/intervention_state.json  # 型付きactionのreservationと証拠link
  defense/driver.finalized.json    # 任意の最終再観測receipt
  defense/recovery.json            # 任意のadapter recovery report
  console/                  # Console専用session record（必要時に作成）
```

各streamは`--attacker-log`、`--defense-log`、`--sensor-log`、`--driver-log`で個別指定できます。
明示的な空値はそのstreamを無効化します。対応する環境変数は`python server.py --help`でも
確認できます。**Export**がdownloadするのはmergeしたJSONL streamです。型付きactionの完全な
証跡chainが必要な場合は、JSON state・finalization・recoveryのsidecar fileもrun directoryと
一緒に保存してください。これらはJSONL exportには埋め込まれません。

## Defender viewの見方

- 観測したtelemetryは折りたためるbatchにまとめます。2秒を超える間隔で新しいbatchになり、
  自分で開閉していない古いbatchは自動で折りたたまれます。
- Antigent自身の動きは折りたたみません。turnの表示、Antigentの操作、`HONEYTOKEN TRIGGERED`は
  batchの間に置かれ、その時点のbatchを区切ります。
- **raw: on/off**は外部clientからの低レベルなrequestの表示・非表示を切り替えます。Antigentは
  観測を続けており、変わるのは表示だけです。
- タイトルの**N internal**はlab内のservice同士（とDocker host）の通信の件数です。Antigentの
  観測対象外で、表示はしません。
- paneの一番下を見ているときは新しい項目に追従し、上にscrollしているときは位置を保ちます。

## デモ受入チェック

- **Attacker**、**Defender view**、**Antigent**の3 paneが表示される。
- live agentなしで、攻撃者commandと防御側assessment/actionが再生される。
- target healthはsensorのstatus file（Dockerが報告するcontainer状態）に基づき、replayがoffline targetをhealthyに見せない。
- **Export**が選択したrun directoryのJSONLをdownloadでき、JSON sidecar fileは同じdirectoryに
  別途保存される。
- UIにcommand入力はなく、serverにもcommand endpointはない（HTTP 404）。
- replay開始によってtarget build、target file変更、model呼び出しが発生しない。

デモの実行は[usage.md](usage.md)を参照してください。runの要約は`python3 eval/metrics.py runs/demo`で出せます。
