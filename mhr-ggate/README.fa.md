# mhr-ggate

> 🇬🇧 [English README](README.md)

تونل واقعی VMess + xhttp از طریق Google Apps Script به VPS شخصی شما.
بر اساس ایده‌ی اصلی `mhr-cfw` ساخته شده، اما با یه تونل واقعی xray
زیرش — یعنی UDP، بازی، و هر اپ TCP-بنیادی واقعاً کار می‌کنه (نه فقط HTTP).

```
کلاینت xray (SOCKS5 / HTTP)
   └── 127.0.0.1:8000  client_relay.py        # هر درخواست رو base64 می‌کنه
            └── https://script.google.com/macros/s/.../exec   # GAS Web App
                     └── https://your-vps      # nginx + TLS
                              └── 127.0.0.1:8080  server.py   # base64 رو باز می‌کنه
                                       └── 127.0.0.1:10000  xray (vmess+xhttp)
                                                └── اینترنت
```

GAS روی دامنه‌ی گوگل اجرا می‌شه و عملاً فیلتر نمی‌شه. IP سرور شما هم
هیچ‌وقت مستقیم از سمت کلاینت دیال نمی‌شه — فقط GAS بهش وصل می‌شه. کل
ترافیک هم داخل یه تونل واقعی VMess می‌مونه، پس UDP و بازی همون‌طور
کار می‌کنه که روی یه VMess معمولی کار می‌کنه.

---

## چه چیزی نسبت به نسخه‌ی اول عوض شد

نسخه‌ی اول می‌خواست xray رو مستقیم به `script.google.com` با SplitHTTP+TLS
وصل کنه. عملاً این کار نمی‌کنه:

| مشکل | چرا شکست می‌خورد |
|---|---|
| GAS پروتکل VMess رو نمی‌فهمه | TLS handshake کلاینت با GAS هیچ‌وقت تبدیل به پاسخ سرور VMess نمی‌شه |
| داده‌ی باینری در GAS خراب می‌شه | `e.postData.contents` رشته است؛ بایت‌های VMess به‌هم می‌ریزن |
| long-poll SplitHTTP × سقف ۶ دقیقه‌ی GAS | پایه‌ی download در حالت پیش‌فرض یه استریم بلنده، اما هر اجرای GAS کوتاه‌مدته |
| بدون چک امنیت و مدیریت خطا | secret پاس می‌شد ولی هیچ مقایسه‌ی constant-time نبود |

این بازنویسی همه رو حل می‌کنه:

1. **اضافه شدن `client_relay.py` محلی** — بین xray و GAS قرار می‌گیره،
   هر body رو خروجی base64 می‌کنه و در پاسخ هم decode می‌کنه. باینری
   صحیح به VPS می‌رسه.
2. **سوییچ به transport `xhttp` با `mode = "packet-up"`** — هر درخواست
   کوتاه و مستقله. هیچ long-poll‌ای که GAS نتونه serve کنه وجود نداره.
3. **هاردنینگ `server.py`**: decode صریح base64، چک constant-time
   secret، سقف اندازه‌ی payload، logging ساختاریافته، endpoint
   `/_mhr/stats`، retry با backoff در سمت کلاینت.
4. **همراهش همه چیزی که برای واقعا اجرا کردنش لازمه**: اسکریپت نصب،
   systemd unit، تمپلیت nginx، Docker compose، تست‌ها، لانچر ویندوز.

---

## نیازمندی‌ها

- یه VPS خارج از ایران (هر پروایدر، هر سایز)
- یه حساب گوگل رایگان
- [xray-core](https://github.com/XTLS/Xray-core) روی VPS (اسکریپت
  خودش نصب می‌کنه)
- Python 3.10+ روی VPS **و روی دستگاه شخصی** (برای relay محلی)
- یه کلاینت سازگار با v2ray (همون CLI `xray` کافیه، یا v2rayN /
  NekoBox / Hiddify اگه لینک vmess:// رو import می‌کنی)

---

## شروع سریع

### ۱. کلون

```bash
git clone https://github.com/Vuks1n/mhr-ggate
cd mhr-ggate
```

### ۲. نصب VPS (یه دستور)

روی یه VPS تازه‌ی Debian/Ubuntu (با root):

```bash
SECRET="$(openssl rand -hex 24)"
sudo bash scripts/install_server.sh \
    --domain vpn.example.com \
    --email  you@example.com \
    --secret "$SECRET"
```

اسکریپت xray رو نصب می‌کنه، `/opt/mhr-ggate` رو می‌سازه، یه
`mhr-relay.service` می‌نویسه، nginx رو با Let's Encrypt راه می‌اندازه،
و در پایان UUID و SECRET رو که برای مرحله‌ی بعد لازمه چاپ می‌کنه.

دامنه نداری؟ `--no-tls` بزن، self-signed درست می‌کنه. (در سمت Code.gs
باید `validateHttpsCertificates: false` کنی — توضیحاتش توی فایل هست.)

می‌تونی به جاش با Docker هم اجرا کنی — `docker/docker-compose.yml`.

### ۳. دیپلوی GAS Web App

1. برو <https://script.google.com> → **New project**
2. محتوای `gas/Code.gs` رو پیست کن
3. دو ثابت بالای فایل رو پر کن:

   ```js
   var VPS_URL = "https://vpn.example.com";
   var SECRET  = "...";   // همون SECRET که به install_server.sh دادی
   ```

4. **Deploy → New deployment → Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**

5. URL دیپلوی رو کپی کن — چیزی شبیه
   `https://script.google.com/macros/s/.../exec`.

### ۴. ساخت کانفیگ کلاینت

روی دستگاه خودت:

```bash
pip install -r requirements.txt

python3 v2ray/generate_config.py \
    --gas-url "https://script.google.com/macros/s/.../exec" \
    --secret  "$SECRET" \
    --uuid    "$UUID"      # UUID که install_server.sh چاپ کرد
```

سه فایل توی پوشه‌ی فعلی می‌سازه:

- `relay.toml` — کانفیگ `client_relay.py`
- `client_config.json` — کانفیگ کلاینت xray
- `mhr.vmess` — یه لینک vmess:// قابل import (به relay محلی اشاره می‌کنه)

### ۵. اجرا

#### Linux / macOS

```bash
bash scripts/run_client.sh
```

#### Windows (PowerShell)

```powershell
pwsh scripts\run_client.ps1
```

#### دستی

```bash
# ترمینال ۱
python3 v2ray/client_relay.py --config relay.toml

# ترمینال ۲
xray run -config client_config.json
```

در هر صورت در نهایت این‌ها در دسترس می‌شن:

- `socks5://127.0.0.1:1080`
- `http://127.0.0.1:8118`

مرورگر، لانچر بازی، یا اپ‌هات رو این‌ها بزن.

---

## بازی / UDP

لانچر رو SOCKS5 `127.0.0.1:1080` تنظیم کن. روی ویندوز می‌تونی از
[Proxifier](https://www.proxifier.com/) استفاده کنی تا هر بازی‌ای رو
حتی بدون پشتیبانی داخلی SOCKS5 از تونل رد کنی.

UDP داخل تونل VMess با xudp mux پیچیده می‌شه — بازی و voice دقیقاً
همون‌طور کار می‌کنن که روی یه لینک VMess معمولی کار می‌کنن.

---

## معماری

برای دیدن نمودار توالی و توضیح دیسیپلین base64 wrapping به
[docs/architecture.md](docs/architecture.md) نگاه کن.

```
mhr-ggate/
├── gas/
│   └── Code.gs                   # توی Google Apps Script پیست کن
├── server/
│   ├── server.py                 # relay سمت VPS (FastAPI)
│   └── xray_server.json          # کانفیگ inbound xray (vmess + xhttp)
├── v2ray/
│   ├── client_relay.py           # relay محلی بین xray و GAS
│   └── generate_config.py        # تولید relay.toml + client_config.json + mhr.vmess
├── scripts/
│   ├── install_server.sh         # نصب یه‌خطی VPS
│   ├── mhr-relay.service         # systemd unit برای server.py
│   ├── mhr-client-relay.service  # systemd unit برای client_relay.py (لینوکس کلاینت)
│   ├── nginx.conf.template
│   ├── run_client.sh             # لانچر لینوکس (relay + xray)
│   └── run_client.ps1            # لانچر ویندوز
├── docker/
│   ├── Dockerfile.server
│   └── docker-compose.yml
├── tests/                         # ۳۸ تست unit و e2e، شامل round-trip باینری
└── requirements.txt
```

---

## مانیتورینگ

هر دو relay یه endpoint کوچک stats دارن که با `MHR_SECRET` محافظت شدن:

```bash
curl -H "X-MHR-Secret: $SECRET" https://vpn.example.com/_mhr/stats
curl http://127.0.0.1:8000/_mhr/stats
```

تعداد درخواست، شمارنده‌های بایت و آخرین خطا رو برمی‌گردونه.

---

## تست

```bash
pip install -r requirements.txt
pip install pytest
python -m pytest tests/ -v
```

تست‌ها شامل یه pipeline کامل هستن که `client_relay → GAS فیک →
server.py → xray فیک` رو بدون هیچ تماس شبکه به‌هم وصل می‌کنه و ثابت
می‌کنه یه payload باینری ۱ مگابایتی بایت‌به‌بایت سالم برمی‌گرده.

---

## محدودیت‌هایی که باید بدونی

- **سهمیه‌ی GAS**: حساب گوگل رایگان روزانه حدود ۲۰ هزار URL fetch
  می‌ده. برای استفاده شخصی به اندازه‌ی کافیه، برای استریم 4K کمتر.
  اگه به سقف خوردی یه Web App دیگه از یه حساب دوم دیپلوی کن و دو
  client_relay با `gas_url` متفاوت اجرا کن.
- **تأخیر**: هر پکت `client → GAS → VPS → xray → VPS → GAS → client`
  رو طی می‌کنه. حدود ۶۰–۲۰۰ms اضافه نسبت به اتصال مستقیم انتظار
  داشته باش. برای مرور و بازی خوبه؛ برای دانلود سنگین طولانی نه.
- **نسخه‌ی xray**: transport `xhttp` نیاز به xray-core ≥ 1.8.16 داره
  (یا فورک v2fly معادل). اسکریپت نصب همیشه آخرین نسخه رو می‌گیره.

---

## کردیت‌ها

- [mhr-cfw](https://github.com/denuitt1/mhr-cfw) — ایده‌ی اصلی استفاده از GAS به‌عنوان relay
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — تونل اصلی

PR خوش‌آمدید.
