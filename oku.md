Bu proje, başlangıçta çeşitli Google dork sorgularıyla görünür hale gelen yanlış yapılandırma ve dosya sızıntısı senaryolarını, daha kontrollü ve pratik bir yapıya dönüştürme fikriyle ortaya çıktı. Amaç, arama motoru sorgularına bağımlı kalmak yerine, doğrudan belirlenen bir hedef 
üzerinde çalışan,  ve modüler bir açık yüzey tarama programı geliştirmekti.
-------------------------<<<<<<
----------------------->>>>>>>>>
Google dork mantığı, arama motorunun indekslediği açık içerikleri bulmak için kullanılır. -
A.	-sonuçlar gecikmeli olabilir
B.	-arama motorunun neyi gördüğüne bağımlıdır
C.	-sürekli ve kontrollü test için uygun değildir

Bu projede bu yaklaşım değiştirilerek, dork ifadelerindeki mantık path + içerik eşleşmesi modeline çevrildi. Yani araç artık inurl:.env "DB_PASSWORD" gibi sorgular üretmek yerine, doğrudan hedefte:

/.env
/config/.env
/.git/config
/phpinfo.php
/storage/logs/laravel.log
/swagger.json
/horizon/dashboard
/actuator/env
/adminer.php
Nasıl çalışır?

Araç üç temel dosyadan oluşur:
------
-yr.py-
------
Kullanıcı arayüzüdür. Program açıldığında banner gösterir, kullanıcıdan hedef alır, 
parametreleri yorumlar ve taramayı başlatır.
------
-core.py-
-------
Tarama motorudur. HTTP isteklerini atar, response body okur, kurallarla eşleştirme yapar, 
bulguları ekrana yazdırır ve JSON çıktısı üretir.
------
-rules.py-
-------
Tarama kurallarını tutar. Hangi path’lerin deneneceği, hangi regex’lerin aranacağı, hangi bulguya hangi açıklamanın ve remediation bilgisinin ait 
olduğu burada tanımlanır. Ek olarak istedğiniz dorkları bu mantımkta rules.py dosyhasına ekleyebiliriz ve kendinize özgü bir tarama modeli geliştirebilirisniz. 
En bilindik dorklar baz alınarak geliştirilmiştir.
---------
--KURULUM--
----------
git clone https://github.com/Altanay/YR6.git
cd YR6
ls
pip install -r requirements.txt
python3 yr.py
Açıldığında bizden URL isteyecek

<<<Kullanımı>>>>>
https://example.com
https://example.com -w 20
https://example.com -k
https://example.com -w 20 -k -o sonuc.json
https://example.com https://2,example.com -w 15

PARAMETRE AÇIKLAMALARI
-w => workers
Aynı anda kaç paralel iş parçacığıyla tarama yapılacağını belirler.
-k => insecure
TLS/SSL sertifika doğrulamasını kapatır. 
-o => output yani çıktı
