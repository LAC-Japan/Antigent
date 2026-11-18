# Optionalなbuild時CA bundle

build hostがTLS-inspecting proxyの背後にある場合、またはegressがTCP 443のみに
制限されている場合（plain HTTPのDebian mirrorに到達できない場合）、combined CA
bundle（システムルート + proxyのCA）を`combined-ca-bundle.pem`という名前でこの
ディレクトリに置いてください。あるいは`ANTIGENT_CA_CONTEXT` build変数でそのファイルを
含むディレクトリを指定してください。image buildはHTTPSのDebian mirrorとこのbundleを
使ってaptとtool downloadのTLS**検証**を行います（検証を無効化することはありません）。
Attack Box sampleも`ATTACKER_CA_CONTEXT`を通じて同じ規約を使います
（version固定のscanner downloadを含む）。
defense imageはこのbundleをCA storeにも追加するため、同じproxyの背後でもdefenderの
model呼び出しが通ります。Attack Boxは実行時に`CA_BUNDLE_PATH`で受け取ります
（`examples/attacker/.env.example`参照）。

**言語:** [English](README.md) | 日本語

変更していないcheckoutでは、このディレクトリにはこのファイルだけが入っています。
その場合、名前付きbuild contextにはbundleがなく、buildはimageのシステムルートを
使います。
