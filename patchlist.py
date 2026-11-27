import hashlib
import hmac
import json
import time
import urllib.parse
import urllib.request

URL = "https://passport.papegames.com/v1/accessories/gameconfig/patchlist_v2"
APP_KEY = "611A520DA5C72545"

params = {
    "app_id": "5510010",
    "channel": "3",
    "clientid": "1106",
    "env": "prod",
    "region": "1",
    "sign_type": "hmac",
    "timestamp": str(int(time.time())),
}

unsigned_body = urllib.parse.urlencode(sorted(params.items()))
sign = hmac.new(
    APP_KEY.encode(),
    unsigned_body.encode(),
    hashlib.md5,
).hexdigest()

request = urllib.request.Request(
    URL,
    data=f"{unsigned_body}&sign={sign}".encode(),
    headers={"Content-Type": "application/x-www-form-urlencoded"},
    method="POST",
)

with urllib.request.urlopen(request, timeout=20) as response:
    result = json.load(response)

if result.get("code") != 0:
    raise RuntimeError(
        f"请求失败：code={result.get('code')}, "
        f"info={result.get('info')}, "
        f"request_id={result.get('request_id')}"
    )

urls = result["data"]["game_config_patch"]["extra"]["cdn_url"].split(";")

print("主地址：", urls[0])
if len(urls) > 1:
    print("备用地址：", urls[1])

manifest_url = result["data"]["game_config_apk"]["diff_file_download_address"]
with urllib.request.urlopen(manifest_url, timeout=20) as response:
    manifest = json.load(response)

package = manifest["latest"]
print("本体清单：", manifest_url)
print("本体版本：", package["version"])
print("本体地址：", package["url"])
print("本体 MD5：", package["md5"])
