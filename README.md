# appsec-cloud
Отчёт по тестовому заданию на AppSecCloudCamp


## 1. Вопросы для разогрева

1. Расскажите, с какими задачами в направлении безопасной разработки вы сталкивались? 

С данными задачами встречаюсь впервые.

2. Если вам приходилось проводить security code review или моделирование угроз, расскажите, как это было? 
-
3. Если у вас был опыт поиска уязвимостей, расскажите, как это было? 

Участвовал в некоторых CTF, последний значительный был от Тинькофф в прошлом году. Проходил различные задания и комнаты, на таких сервисах как TryHackMe и HackTheBox. Вот ссылка на мой профиль THM: https://tryhackme.com/p/Nmazgaleev, сразу скажу, что давно не выполнял там задания.

4. Почему вы хотите участвовать в стажировке?

На данный момент времени, я обучаюсь на 3 курсе по специальности «Обеспечение информационной безопасности автоматизированных систем» и хотел бы выбрать что-то определенное для себя. Меня всегда интересовала разработка, ещё со школы занимался программированием и изучал всё связанное с этим самостоятельно. На протяжении пары лет писал различные проекты: подобие физических движков, песочниц, симуляций различных физических явлений. Меня интересует, как информационная безопасность, так и разработка различных сервисов.
Через рекламу на веб-ресурсах узнал о стажировке в AppsSec, подал заявку. Я бы хотел связать свою дальнейшую карьеру с интересующими меня направлениями, поэтому я рассматриваю данную стажировку как возможность усовершенствовать свои существующие навыки и начать карьеру в AppsSec.


## 2. Security code review
### Часть 1. Security code review: GO
Рассмотрев представленный в примере код, я нашёл только одну уязвимость. В функции «searchHandler» выполняется запрос к базе данных, на выходе мы получаем список товаров. Сам SQL запрос можно увидеть на 38 строчке, где из заголовка GET-запроса приложение получает наименование товара и совмещает это с заготовленным запросом. Рассмотрев всё это, можно сказать, что данный фрагмент кода уязвим к SQLi. Данная уязвимость позволяет злоумышленнику изменять содержимое SQL запроса и получать данные, к которым он не имеет доступ.
```
    query := fmt.Sprintf("SELECT * FROM products WHERE name LIKE '%%%s%%'", searchQuery)
    rows, err := db.Query(query)
    if err != nil {
        http.Error(w, "Query failed", http.StatusInternalServerError)
        log.Println(err)
        return
    }
```
Для устранения данной уязвимости можем предоставлять значения параметров SQL в качестве аргументов функции, так как пакет sql в golang осуществляет проверку на данную уязвимость. Решая данную задачу, я даже наткнулся на страницу документации golang, где представлен пример как не следует выполнять SQL запросы, ознакомиться можно по ссылке https://go.dev/doc/database/sql-injection. Исправленный фрагмент кода представлен.
```
    rows, err := db.Query("SELECT * FROM products WHERE name LIKE ?", searchQuery)
    if err != nil {
        http.Error(w, "Query failed", http.StatusInternalServerError)
        log.Println(err)
        return
    }
    defer rows.Close()
```

### Часть 2: Security code review: Python
<!-- Указать строки, в которых присутствуют уязвимости. -->

В примере 2.1, 
Рассмотрим пример 2.1. После анализа, я заметил возможность наличия уязвимости на строчках 9-11, где по значениям в заголовке GET-запроса с аргументами «name», «age» и «unknown» устанавливаются значения переменным «name» и «age». После чего данное веб-приложение отображает содержимое этих переменных без каких-либо проверок, что позволяет нам воспользоваться XSS-атакой.
```
from flask import Flask, request
from jinja2 import Template

name = "main"
app = Flask(name)

@app.route("/page")
def page():
    name = request.values.get('name')
    age = request.values.get('age', 'unknown')
    output = Template('Hello ' + str(name) + '! Your age is ' + age + '.').render()
    return output

if name == "main":
    app.run(debug=True)
```
Запустив локально программу, я проверил наличие XSS-уязвимости, указав в качестве имени «<script>alert(document.cookie)</script>», что привело к следующему результату.

![](https://github.com/SopaDePo1lo/appsec-cloud/blob/main/python-example1/1.png)
Данная уязвимость может позволить злоумышленнику провести кражу авторизационных cookie пользователей веб-приложения.

Для устранения данной уязвимости я решил производить проверку вводимых параметров на наличие специальных символов. В нашем случае приложение получает имя и возраст, так что возможность удаления лишних символов из имени исключена. Ниже представлен исправленный код. 
```
from flask import Flask, request
from jinja2 import Template

def parse_input_value(value : str) -> str:
    forbidden_chrs = set([*"<>/&%"])
    return ''.join([c for c in value if c not in forbidden_chrs])


name = "main"
app = Flask(name)

@app.route("/page")
def page():
    name = parse_input_value(str(request.values.get('name')))
    age = parse_input_value(request.values.get('age', 'unknown'))
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
    return output

if name == "main":
    app.run(debug=True)
```
После чего я повторно запустил приложение и провёл попытку XSS-атаки, результат представлен ниже.
![](https://github.com/SopaDePo1lo/appsec-cloud/blob/main/python-example1/2.png)

Также, одним из вариантов устранения уязвимости может использоваться библиотека escape. Она не позволяет выполнять код в данных, переданных пользователем. Реализация представлена ниже.
```
from flask import Flask, request
from jinja2 import Template
from markupsafe import escape

name = "main"
app = Flask(name)

@app.route("/page")
def page():
    name = escape(request.values.get('name'))
    age = escape(request.values.get('age', 'unknown'))
    output = Template('Hello ' + name + '! Your age is ' + age + '.').render()
    return output

if name == "main":
    app.run(debug=True)
```
Результат попытки атаки представлен ниже.
![](https://github.com/SopaDePo1lo/appsec-cloud/blob/main/python-example1/3.png)

Если выбирать наилучший вариант реализации исправления данной уязвимости, то я бы выбрал второй вариант с использованием дополнительного функционала flask. По сути, обе реализации осуществляют схожие действия: они обе проверяют данные на наличие дополнительных символов, но реализация flask не удаляет эти символы, а заменяет их на безопасные для HTML-последовательности.

Рассмотрим пример 2.2, код которого представлен ниже.
```
from flask import Flask, request
import subprocess

name = "main"
app = Flask(name)

@app.route("/dns")
def dns_lookup():
    hostname = request.values.get('hostname')
    
    cmd = 'nslookup ' + str(hostname)
    output = subprocess.check_output(cmd, shell=True, text=True)
    return output

if name == "main":
    app.run(debug=True)
```
На строках 8-11 я обнаружил возможную уязвимость. На 8 строчке приложение берёт значение «hostname» из заголовка GET-запроса пользователя, после чего совмещает с командой «nslookup» и запускает в командной строке. Результат выполнения команды отображается на сайте.
![](https://github.com/SopaDePo1lo/appsec-cloud/blob/main/python-example2/%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%802.2.png)

Запустив данное приложение локально, я отправил запрос, указав в качестве «hostname» значение «8.8.8.8 & ipconfig», тем самым получив информацию о сетевых устройствах системы, на которых работает данный сервис. Злоумышленник может воспользоваться данной уязвимостью для запуска любого кода на системе сервера, имея соответствующие права. Вкратце, получаем полный доступ к терминалу хоста, после чего можем даже настроить reverse shell, тем самым уже получаем полный доступ к системе с правами сервера.
Для устранения данной уязвимости я решил провести проверку на вводимых значениях «hostname», а именно удалять часть строки после специального символа «&» и «;». Так, при любом запросе от пользователя, будет выполняться только команда «nslookup». Код представлен ниже.
```
from flask import Flask, request
import subprocess

name = "main"
app = Flask(name)

@app.route("/dns")
def dns_lookup():
    hostname = request.values.get('hostname')
    cmd = 'nslookup ' + str(hostname).split("&")[0].split(";")[0]
    output = subprocess.check_output(cmd, shell=True, text=True)
    return output

if name == "main":
    app.run(debug=True)
```
Результат попытки эксплуатировать уязвимость после изменений представлен ниже.
![](https://github.com/SopaDePo1lo/appsec-cloud/blob/main/python-example2/%D0%BF%D1%80%D0%B8%D0%BC%D0%B5%D1%802.2..png)

Также, в качестве решения уязвимости можно, аналогично первому примеру на Python, удалять специальные символы из вводимых пользователем данных. 
<!-- Если уязвимость можно исправить несколькими способами, необходимо перечислить их, выбрать лучший по вашему мнению и аргументировать свой выбор. -->

