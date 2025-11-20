# Happ-RE
Happ - это закрытый VPN/прокси клиент без исходного кода, с умеренным уровнем обфускации внутри основной функции onCreate которая содержит анти-тампер.  

С точки зрения RE это интересная цель:
- нет исходников
- код обфусцирован
- есть крипта и integrity проверки
- ключи шифрования встроены в приложение и юзерам их видеть "не положено"

## Цель RE
Есть одна вкусная штука - **зашифрованные подписки**.

По документации:
- Happ такие ссылки выглядят как `happ://crypto...` или новая форма `happ://crypt3/...` для RSA-4096
- Идея проста:
  - шифруется сама ссылка на подписку (URL), то есть настоящий адрес подписки юзер увидеть не может
  - после добавления такой подписки юзер:
    - не может просматривать конфиги серверов
    - не может редактировать их
    - не может поделиться ими как обычным сырым конфигом  
  - ключи шифрования встроены в приложение, снаружи их не видно

То есть по задумке разработчика:
- у тебя есть шифрованная подписка
- Happ скачивает и расшифровывает конфиг внутри себя
- а ты как юзер видишь только "серверы", но не можешь вытащить **сырой конфиг**

Шифрование ссылок можно делать тремя способами (по их же докам):
- через страницу на сайте Happ
- через API `https://crypto.happ.su/api.php`
- вручную через публичный RSA ключ (в том числе RSA-4096 для `happ://crypt3`)

Пример API из документации Happ:

`curl -X POST -H "Content-Type: application/json" -d '{"url":"https://your_url.com"}' "https://crypto.happ.su/api.php" `

API возвращает зашифрованную версию ссылки, которую уже можно скормить приложению.

Из этого рождается вполне понятное желание:
- мы хотим не только добавлять такие подписки
- но и понимать, что именно Happ из них вытягивает
- а значит - получить **сырой конфиг**, который уже внутри клиента существует в расшифрованном виде

### Как Happ проверяет подпись apk

При пересборке и подписи своим ключом приложение начинало крашить сразу при запуске. В логах это выглядело примерно так:
```
FATAL EXCEPTION: main
java.lang.RuntimeException: Unable to start activity ... MainActivity: java.lang.NullPointerException
Caused by: java.lang.NullPointerException
    at su.happ.proxyutility.feature.main.MainActivity.onCreate(...)
```
Разбор показал, что внутри `MainActivity.onCreate()` приложение дергает статическое поле из `HappApplication`, что-то вроде:
```java
String str = HappApplication.h0;
Intrinsics.checkNotNull(str);
mainViewModel.m9762u(str);
```
Если `h0 == null` - сразу NullPointerException. В оригинальном apk `h0` инициализируется в `Application.onCreate()`. В пересобранном - нет, поскольку не совпадает подпись, и она затирается.

Дальше находим в `HappApplication.onCreate()` интересный фрагмент:

Я приведу это в более читаемый вид:
```java
List parts = split("uWM0lcVs0849kTwk?AqHnQy35aOM/ZtgUip+BrTHHLnSYBNwQAX0y2g==?os8iL1DE8Dee/5roJ+ZzsQ==", "?");

String current = clean(z8.e(this).get(0));
String expected = yq0.b(parts[1], parts[0], parts[2]);

if (!current.equals(expected)) {
    yq0.e();
    xq0.d();
    HappApplication.h0 = null;
}
```
Здесь мы видим:
- `z8.e(HappApplication)` - метод, который:
 - берёт подпись приложения через `PackageManager.getPackageInfo(...)`
- считает SHA по подписи
- кодирует в Base64
- возвращает список таких строк (по сути отпечаток подписи)
- `yq0.b(...)` - функция, которая из трёх зашитых кусков (base64/ключ/соль) собирает правильное значение для оригинального apk

Итог:
- если подпись появилась не та (пересобрали apk, подписали своим ключом) - сравнение не проходит
- запускается ветка "ломаем всё":
  - какие-то методы `yq0.e()`, `xq0.d()` (скорее всего, чистка/логирование, мне лень разбираться пока-что)
  - и самое гадское - `h0 = null`
- дальше `MainActivity` пытается использовать `h0` и ловит NullPointerException на старте

---

Что такое z8.e - как вычисляется подпись

Метод `z8.e(HappApplication)` в декомпилированном виде:

public static List e(HappApplication happApplication) {
    List result;
    iq0 empty = iq0.N; // пустой список

    try {
        if (Build.VERSION.SDK_INT >= 28) {
            SigningInfo info = happApplication
                .getPackageManager()
                .getPackageInfo(happApplication.getPackageName(), 134217728)
                .signingInfo;

            if (info == null) {
                result = empty;
            } else if (info.hasMultipleSigners()) {
                Signature[] apkSigners = info.getApkContentsSigners();
                result = new ArrayList(apkSigners.length);
                for (Signature s : apkSigners) {
                    MessageDigest md = MessageDigest.getInstance("SHA");
                    md.update(s.toByteArray());
                    result.add(Base64.encodeToString(md.digest(), 0));
                }
            } else {
                Signature[] history = info.getSigningCertificateHistory();
                result = new ArrayList(history.length);
                for (Signature s : history) {
                    MessageDigest md = MessageDigest.getInstance("SHA");
                    md.update(s.toByteArray());
                    result.add(Base64.encodeToString(md.digest(), 0));
                }
            }
        } else {
            Signature[] signatures = happApplication
                .getPackageManager()
                .getPackageInfo(happApplication.getPackageName(), 64)
                .signatures;

            if (signatures == null) {
                result = empty;
            } else {
                result = new ArrayList(signatures.length);
                for (Signature s : signatures) {
                    MessageDigest md = MessageDigest.getInstance("SHA");
                    md.update(s.toByteArray());
                    result.add(Base64.encodeToString(md.digest(), 0));
                }
            }
        }
    } catch (Throwable th) {
        if (th instanceof InterruptedException || th instanceof CancellationException) {
            throw th;
        }
        result = vq2.n(th);
    }

    if (je3.a(result) == null) {
        empty = result;
    }
    return empty;
}

Видим:
- достаём подписи из пакета
- считаем SHA по каждой
- кодируем в Base64
- получаем список строк типа "g7a...=="

И одна из этих строк сравнивается с эталонным значением из `yq0.b(...)`.

---

Как я убрал проверку подписи
Исходный smali-фрагмент

В smali в `HappApplication.onCreate` интересующий нас кусок выглядел так:

invoke-virtual {vX, vY}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z
move-result v0

if-nez v0, :cond_0

    .line 82
    invoke-static {}, Lyq0;->e()V

    .line 86
    sget-object v0, Lxq0;->a:Ljava/util/ArrayList;
    invoke-static {}, Lxq0;->d()V

    .line 91
    sput-object v2, Lsu/happ/proxyutility/HappApplication;->h0:Ljava/lang/String;

:cond_0
sget v0, Lx13;->ic_unfold_24dp:I

Логика:
- `if-nez v0, :cond_0`  
Самый тупой, но рабочий патч - просто выкинуть сердцевину if-а.

Было:
```smali
if-nez v0, :cond_0

invoke-static {}, Lyq0;->e()V
sget-object v0, Lxq0;->a:Ljava/util/ArrayList;
invoke-static {}, Lxq0;->d()V
sput-object v2, Lsu/happ/proxyutility/HappApplication;->h0:Ljava/lang/String;

:cond_0
sget v0, Lx13;->ic_unfold_24dp:I
```
Стало:
```smali
if-nez v0, :cond_0

    .line 82
    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    .line 93

:cond_0
sget v0, Lx13;->ic_unfold_24dp:I
```
Дальше:
- пересобираем apk через apktool
- ставим на устройство

Теперь приложение:
- спокойно стартует
- не падает в `MainActivity.onCreate`
- и мы можем дальше ковырять логику, уже изнутри рабочего клиента

Спасибо что дочитали этот кринж, а я пойду поем пожалуй...
