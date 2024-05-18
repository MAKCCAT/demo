Порт группы: HQ BRANCH INTERNET
# *****************Module_1*****************
навсякий https://disk.yandex.ru/d/L_zygCZ82cjYPw  
# 1 ALL (Name/IPv4/IPv6)
Если в задании не будут использоваться встроенные репозитории, а будет возможность скачивать все пакеты из интернета, необходимо отключить проверку пакетов через cdrom зайдя по пути Nano /etc/apt/sources.list и Закоментировать находящуюся там строку.  
### Name   
```
hostnamectl set-hostname Имя устройства  
newgrp
```
### IP
|Name|Ipv4|mask|Def_get|Ipv6/mask|Def_getv6|DNS|  
|---|---|---|---|---|---|---|  
|CLI-ISP|192.168.0.2|255.255.255.0(24)|192.168.0.1|2001::3:2/120|2001::3:1/120|-|  
|ISP-ClI|192.168.0.1|255.255.255.0(24)|-|2001::3:1/120|-|-|  
|ISP-HQR|10.10.10.2|255.255.255.252(30)|-|2001::7:2/126|-|-|  
|ISP-BRR|10.10.10.6|255.255.255.252(30)|-|2001::7:6/126|-|-|  
|HQR-HQSRV|192.168.1.1|255.255.255.240(28)|-|2001::1:1/124|-|192.168.1.2|  
|HQR-ISP|10.10.10.1|255.255.255.252(30)|-|2001::7:1/126|-|-|  
|HQSRV-HQR|192.168.1.2|255.255.255.240(28)|192.168.1.1|2001::1:2/124|2001::1:1/124|192.168.1.2|  
|BRR-BRSRV|192.168.2.1|255.255.255.248(29)|-|2001::2:1/125|-|192.168.1.2|  
|BRR- ISP|10.10.10.5|255.255.255.252(30)|-|2001::7:5/125|-|-|  
|BRSRV-BRR|192.168.2.2|255.255.255.248(29)|10.10.10.5|2001::2:2/125|2001::2:1/125|192.168.1.2|  
---
![maskv4](https://myeditor.ru/wp-content/uploads/b/8/3/b83c1b85ee91682121df78aca1e4576f.png)  
```ip a```  
```  
apt install network-manager
nmtui
```
В nmtui пройдя по пути Edit a connection — имя интерфейса  
Необходимо настройть ip адреса в соответствии с таблицей адресации  
После настройки необходимо зайти в  
activate a connection и перезагрузить все интерфейсы  
(нажать deactivate и activate на каждом интерфейсе)  
```diff  
Примечание: На интерфейсах находящихся между маршрутизаторами не нужно  
указывать dns, достаточно это сделать на внутренних локальных интерфейсах  
маршрутизаторов. Так же не нужно указывать dns на устройствах ISP и CLI  
(Если иного не указано в задании) так как они не принадлежат нашему домену  
```  
---  

Или  

---  

```  
nano /etc/network/interfaces  
```
Пример v4:  
```  
auto ens256  
iface ens256 inet static   
address 10.10.10.1  
netmask 255. 255.255.0    
gateway 10.10.10.2  
```
Пример v6: 
```
auto ens256 
iface ens256 ine6 static 
address 2001::7:1 
netmask 126 
gateway 2001::7:2
```
после перезагружаем сеть```systemctl restart networking```
# 2 BRR HQR ISP Внутренняя динамическая маршрутизация FRR-OSPF/L3)  
```
apt install frr 
nano /etc/frr/daemons
```
не устанавливается 
```dhcpclient -r```  
```dhcpclient -v```  
изменить параметры на YES для протокола ospfd и ospf6d  
### Настройка OSPF v4
```
vtysh 
conf t  
router ospf 
```
|Name|id|network|area|
|---|---|---|---|
|BRR-ISP|2.2.2.2|10.10.10.4/30|0|
|BRR-BRSRV|2.2.2.2|192.168.2.0/29|1| 
|HQR-ISP|3.3.3.3|10.10.10.0/30|0|
|HQR-HQRSRV|3.3.3.3|192.168.1.0/28|2|
|ISP-BRR|4.4.4.4|10.10.10.4/30|0| 
|ISP-HQR|4.4.4.4|10.10.10.0/30|0| 
|ISP-CLI|4.4.4.4|192.168.3.0/24|3|
---
Пример:
```
router ospf  
ospf router-id 2.2.2.2  
network 10.10.10.4/30 area 0  
network 192.168.2.0/28 area 2
```
```exit```  
После завершения конфигурации в frr написать ```write```  
```nano /etc/sysctl.conf```  
переменную ```net.ipv4.ip_forward=1``` и ```net.ipv6.conf.all.forwarding=1``` 
необходимо раскоментить и сохранинть измнения в файле, и применить изменения командой  
```sysctl –p ```  
```diff
-При каждой перезагрузки прописывать sysctl –p 
```  
### Настройка OSPF v6
```
vtysh
conf t  
router ospf6  
```
|Name|id|area|range/mask|
|---|---|---|---|
|BRR-ISP|0.0.0.2|0.0.0.0|2001::7:4/126|
|BRR-BRSRV|0.0.0.2|0.0.0.0|2001::2:0/125| 
|HQR-ISP|0.0.0.3|0.0.0.0|2001::7:0/126|
|HQR-HQRSRV|0.0.0.3|0.0.0.0|2001::1:0/124|
|ISP-BRR|0.0.0.4|0.0.0.0|2001::7:4/126| 
|ISP-HQR|0.0.0.4|0.0.0.0|2001::7:0/126| 
|ISP-CLI|0.0.0.4|0.0.0.0|2001::3:0/120|
---  
Пример:  
```
router ospf6  
ospf6 router-id 0.0.0.1  
area 0.0.0.0 range 2001::1:0/122  
area 0.0.0.0 range 2001::7:0/126  
```
```exit```
```
interface ens224
ipv6 ospf6 area 0.0.0.0
exit
``` 
После завершения конфигурации в frr написать ```write```  
L3 Пример  соединения: ipv4/mask and ipv6/mask  
```systemctl restart frr```  
# 3 HQ-R (автоматическое распределение IP DHCP)  
```  
apt install isc-dhcp-server  
nano /etc/default/isc-dhcp-server
```  
если в сети подразумевается DHCP-relay ,то  
1 интерфейс в сторону клиента, 2 интерфейс в сторону запроса  
```
INTERFACESv4="ens224 ens256"   
INTERFACESv6="ens224 ens256"
```
так же необходимо раскоментировать команды
---
### IPv4
``` nano /etc/dhcp/dhcpd.conf ```  
Пример DHCP для ipv4 без Relay: 
https://shootnick.ru/ip6_calc/21--1-0/122
https://shootnick.ru/ip_calc/
```
default-lease-time 600;  
max-lease-time 7200;
  
ddns-updates on;  
ddns-update-style interim;
  
authoritative;
    
subnet 192.168. 1.0 netmask 255.255.255. 192 {
 range 192. 168.1.3 192.168.1.63;
 option routers 192.168.1.1;
 option domain-name "hq.work";
 option domain-name-servers 192.168.1.2;
}
```  
Где:  
```ddns-update-style interim``` — способ автообновления базы dns  
```authoritative``` — делает сервер доверенным  
```subnet``` — указание сети  
```range``` — пул адресов определяется количиство узлов маски -2 
```option routers``` — шлюз по умолчанию    
subnet нужно 3 шт  
```diff
-Примечание: после каждого изменения конфигурации необходимо
-перезагружать DHCP сервер для применения конфигурации
```
С помошью 2 команд:
```  
systemctl stop isc-dhcp-server  
systemctl start isc-dhcp-server  
```  
```systemctl enable isc-dhcp-server```  
### IPv6
```nano /etc/dhcp/dhcpd6.conf```
Пример DHCP для IPv6:  
```  
default-lease-time 2592000;  
preferred-lifetime 604800;  
option dhcp-renewal-time 3600;  
option dhcp-rebinding-time 7200;  
allow leasequery;  
  
option dhcp6.info -refresh-time 21600;  
authoritative;  
  
subnet6 2001::1:0/122 {
range6 2001::1:0 2001::1:3e;  
option dhcp6.name-servers 2001::1:2;  
option dhcp6.domain-search "hq.work";
}  
```  
``` apt install radvd ```  
``` nano /etc/radvd.conf ```  
Пример конфигурации Radvd:  
```
interface ens224
{  
MinRtrAdvInterval 3;  
MaxRtrAdvInterval 60;  
AdvSendAdvert on;  
};  
```
Где:  
interface — это имя интерфейса направленного в локальную сеть  
Min и MAX интервалы — это интервалы рассылки объявлений  
AdvSendAdvert — это разрешение на выдачу объявлений от маршрутизатор клиентам  
```  
systemctl stop radvd  
systemctl start radvd  
systemctl enable radvd  
```
# 4 ALL (local user)  
|User|Password|Name|  
|---|---|---|  
|Admin|P@ssw0rd|CLI HQ-SRV HQ-R| 
|Branch admin|P@ssw0rd|BR-SRV BR-R| 
|Network admin|P@ssw0rd|HQ-R BR-R BRSRV| 
---  
```adduser имя```  
Вводим пароль  
Для Root прав команда ```visudo```  
В окне вписываем:  
```  
#User privilege specification  
root   ALL=(ALL: ALL) ALL  
admin  ALL=(ALL: ALL) ALL  
```
# 5 HQ-R ISP (пропускная способность сети iperf3)  
```apt install iperf3```  
Выбрать yes  
```iperf3 -c (ip адрес проверяемой машины) -i1 -t20```  
# 6 HQ-R BR-R (backup)  
```mkdir /mnt/backup```  
### Создаём скрипт на HQR  
```touch /etc/backup.sh```  
Если не зашёл автоматически пишем  
```nano /etc/backup.sh```  
В файле пишем:  
1) Упрашёный вариант:  
```
#!/bin/bash
backup_files="/home /etc /root /boot /opt"

dest="/mnt/backup"

archive_file="backup.tgz"
echo "Backing up $backup_files to $dest/$archive_file"

tar czf $dest/sarchive_file $backup_files

echo "Backup finished"

ls -lh $dest
```  
Где:  
backup_files — копируемые директории  
dest — место куда копируем директории  
day — параметр который указывает день бэкапа  
hostname — имя от кого он выполнился  
archive_file — конечное имя файла  
tar czf — в месте указанное в dest помещает файл с именем указанным  
в archive_file с содержимым указанным в backup_files  
echo — необязательные строки вывода  
```bash (имя_файла)```  
В нашем случае имя backup.tgz  
```tar -xvpzf /mnt/backup/HQ-R-Thursday.tgz -C / --numeric-owner```  
### Перекидываем скрипт по ssh на ISP  
```ssh имя@адрес```  
Пример:  
```ssh network_admin@192.168.1.1```  
После создания скрипта для того что бы распаковать наш backup архив  
можно воспользоваться командой  
```scp /расположение/имя_файла имя@адрес :/расположение/имя_файла```  
Пример:  
```scp /etc/backup.sh network_admin@192.168.2.1:/home/network_admin```  
# 7 HQ-SRV (SSH по порту 3035, средства контролирования трафика)  
```nano /etc/ssh/sshd_config```  
Изменяем порт на 3035  
```systemctl restart ssh```  
```apt install iptables-persistent```  
правило iptables для подмены порта ssh:  
```iptables -t nat -A PREROUTING -d 192.168.1.2/28 -p tcp -m tcp --dport -destination 192.168.1.2:3035```  
(это одна команда)  
```iptables-save > /etc/iptables/rules.v4 ```  
# 8 ALL but dont CLI (контроль доступа до HQ-SRV по SSH со всех устройств)  
если нам необходим доступ только от локальных учётных записей , то шаг 1 необходимо пропустить  
Шаг 1(для доступа по root):  
(HQ-SRV)  
```nano /etc/ssh/sshd_config```  
Где необходимо раскоментировать и прописать yes  
```PermitRootLogin yes``` 
после перезагружаем службу ssh  
```systemctl restart ssh```  
Шаг 2:  
создаём ключ аутентификации ssh  
ssh-keygen -c «имя_устройства_с_которого_создан_ключ»  
везде нажием ENTER пока не создастся ключ  
необходимо перенести публичный ключ, на сервер к которому мы
будем получать доступ  
```ssh-copy-id имя@адрес```  
Пример:  
```ssh-copy-id root@192.168.1.2```  
```ssh-copy-id admin@192.168.1.2```   
(HQ-SRV)   
```nano /etc/hosts.deny```  
и вносим следующую строку в файл  
```sshd: 192.168.0.2``` (адрес машины CLI)  
```systemctl restart ssh```  
В конце не забудьте отключить доступ по root, если иного не указано в задании !  
```nano /etc/ssh/sshd_config```  
```PermitRootLogin no```  
```systemctl restart sshd```
# *****************Module_2*****************  
# 1 HQ-SRV Настройте DNS-сервера  
Зона hq.work  
|Name|P|ip|  
|---|---|---|  
|HQ-R.hq.work|A,PTR|ip|  
|HQ-SRV.hq.work|A,PTR|ip|  
---
Зона hq.work  
|Name|P|ip|  
|---|---|---|  
|BR-R.branch.work|A,PTR|ip|  
|BR-SRV.branch.work|A|ip|  
---
```apt install bind9 dnsutils```    
```nano /etc/bind/named.conf.default-zones```  
Зоны для hq.work
```  
zone "hq.work" {  
  type master;  
  file "/etc/bind/hq";  
  allow-update {any;};  
  allow-transfer {any;};  
};

zone "1.168.192.in-addr.arpa" {  
  type master;  
  file "/etc/bind/hq_arpa";  
  allow-update {any;};  
};
zone "0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa" {  
  type master;  
  file "/etc/bind/hq6_arpa";  
  allow-update {any;};  
};  
```  
где:  
zone — создаваемая зона  
type — выбор между первичным и вторичным dns. (Master и Slave)  
file — расположение конфигурационного файла зоны  
allow-update — разрешение динамических обновлений  
где zone:  
hq.work — зона прямого просмотра  
in-addr.arpa — зона обратного просмотра ipv4  
ip6.arpa — зона обратного просмотра ipv6 (указывается полностью. В обратном порядке)  
Зоны для hq.work
```  
zone "branch.work" {  
  type master;  
  file "/etc/bind/branch";  
  allow-update {any;};  
  allow-transfer {any;};  
};  
  
zone "2.168.192.in-addr.arpa" {  
  type master;  
  file "/etc/bind/branch_arpa";  
  allow-update {any;};  
};  
zone "0.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa" {  
  type master;  
  file "/etc/bind/branch6_arpa";  
  allow-update {any;};  
};  
```    
Следующим шагом необходимо создать конфигурационные вайлы для наших зон. Это можно сделать, скопировав стандартные шаблоны командой cp  
Пример:  
```cp /etc/bind/db.local /etc/bind/hq — создание файла для прямой зоны```    
```cp /etc/bind/db.127 /etc/bind/hq_arpa — создание обратной зоны ipv4```   
Зону для ipv6 скопируем после конфигурации зоны для ipv4 (так как по содержанию они не отличаются)  
```nano /etc/bind/hq```  
```  
;
; BIND data file for local loopback interface
;
$TTL     604800
@        IN      SOA      hq.work.   root.hq.work. (
                                2          ;Serial
                            604800         ;Refresh
                             86400          ;Retry
                           2419200          ;Expire
                            604800 )        ;Negative Cache TTL
;
@        IN      NS       hq.work.      
@        IN      A        192.168.1.2
HQ-SRV   IN      AAAA     2001::1:2
HQ-SRV   IN      A        192.168.1.2
HQ-R     IN      A        192.168.1.1
HQ-R     IN      AAAA     2001::1:1
SERVER   IN      CNAME    HQ-SRV
```  
Где:  
NS запись — обозначение сервера отвественного за разрешение запросов к dns  
A запись — основная запись для зоны прямого просмотра по протоколу ipv4  
АААА запись - запись для зоны прямого просмотра по протоколу ipv6  
CNAME — необязательный параметр, для указания альтернативного имени записи  
```nano /etc/bind/hq_arpa```  
```  
;
; BIND reverse data file for local loopback interface
;
$TTL     604800
@        IN      SOA      hq.work.   root.hq.work. (
                                 1          ;Serial
                            604800          ;Refresh
                             86400          ;Retry
                           2419200          ;Expire
                            604800 )        ;Negative Cache TTL
;
@        IN      NS       hq.work.      
2        IN      PTR      HQ-SRV.hq.work.
1        IN      PTR      HQ-R.hq.work.
```  
Где:  
PTR запись — основная запись для зоны обратного просмотра  
Третьим шагом настроим запись для зоны обратного просмотра для ipv6, для этого достаточно скопировать зону hq_arpa, то есть  
```cp /etc/bind/hq_arpa /etc/bind/hq6_arpa```  
После создания всех конфигов необходимо перезагрузить службу bind9  
```systemctl restart bind9``` (лучше stop и start)  
Похожая настройка выполняется для зоны branch.work  
Проверка выполняется посредством команд  
```  
host IP-адрес  
host имя машины
```  
Примечание:  
Не забывайте, что для br-srv по заданию нет PTR записи, её создание может считаться ошибкой  
2. Настройте синхронизацию времени между сетевыми устройствами по протоколу NTP.  
a. В качестве сервера должен выступать роутер HQ-R со стратумом 5   
b. Используйте Loopback интерфейс на HQ-R, как источник сервера времени   
c. Все остальные устройства и сервера должны синхронизировать свое время с роутером HQ-R  
d. Все устройства и сервера настроены на московский часовой пояс (UTC +3)  

Настройка производится на всех машинах, указанных в топологии, при этом настройка на машине, выступающей в роли NTP сервера уникальна, а на NTP клиентах идентична
Для начала на всех машинах необходимо установить московский часовой пояс, для этого следует воспользоваться командой 
# 2 HQ-R синхронизацию времени между сетевыми устройствами по протоколу NTP
```timedatectl set-timezone Europe/Moscow```  
Следующим шагом установим альтернативную службу NTP, под названием CHRONY, так как для задания 3, где происходит развёртывание домена, будет использоваться именно этот сервис. Устанавливаем с помощью команды:  
```apt install chrony```  
Произведём установку NTP сервиса Chrony  
Далее следует осуществить настройку машины, выступающей в роли NTP сервера HQ-R, посредством команды  
```nano /etc/chrony/chrony.conf```  
осуществим вход в конфигурацию chrony, где следует установить значения:  
```local stratum 5```  
```  
allow 192.168.0.0/8  
allow 10.10.10.0/8  
```  
Примечание: Нет необходимости указывать все сети которые присутствует в нашей сети, достаточно указать только одну сеть каждой машины , а так как у нас используется сети 192.168.0.0 , 192.168.1.0 и 192.168.2.0 , есть возможность взять сеть 192.168.0.0 с 22 маской которая будет включать в себя сеть начинающуюся с адреса 192.168.0.0 и заканчивающаяся адресом 192.168.3.255  
Для настройки NTP клиентов chrony так же необходимо перейти в конфиг  
```nano /etc/chrony/chrony.conf```  
И необходимо провести внести изменения в конфиг   
```
#Use Debian vendor zone.  
#pool 2.debian.pool.ntp.org iburst  
server 192. 168.1.1  
```
Для проверки используйте команды ```chronyc tracking``` и ```chronyc sources```
# 3 HQ-SRV Настройте сервер домена выбор, его типа обоснуйте, на базе HQ-SRV через web интерфейс  
Первым делом необходимо установить докер, воспользовавшись скриптом, который есть в открытом доступе, однако для этого нам необходимо экспортировать переменные окружения относящиеся к Proxy (Если Proxy отсутствует т. е. Пакеты с не стандартных репозиториев устанавливаются сами, то первый шаг можно пропустить)  
Первым шагом необходимо посмотреть переменные, которые необходимо экспортировать, перейдя по пути
```nano /etc/apt/apt.conf.d/01proxy```  
и посмотреть находящиеся там значения, после чего посредством команд  
```export http_proxy=http(или https)://(адрес:порт)```  
```export https_proxy=http(или https)://(адрес:порт)```  
Экспортировать переменные прокси для доступа в интернет  
ПРИМЕР:  
```
Acquire::http::Proxy "http://10.0.70.52:3128";
Acquire::https::Proxy "http://10.0.70.52:3128";
# END ANSIBLE MANAGED BLOCK
```
Команды для экспортирования переменных  
```
export http_proxy=http://10.0.70.52:3128
export https_proxy=http://10.0.70.52:3128
```
Вторым шагом посредством скрипта необходимо установить сам DOCKER, для этого необходимо ввести следующую команду  
```wget -qO- https://get.docker.com | bash ```  
Вся установка происходит автоматически, и не должна выдавать ошибок, если были выполнены все предыдущие шаги  
Третьим шагом необходимо запулить готовый контейнер с образом freeipa для centos-8-4.8.4 Для этого создаём каталог для автоматического запуска служб докера (Необходимо если вы делали шаги с Proxy ранее), командой  
```mkdir -p /etc/systemd/system/docker.service.d```  
Далее заходим в файл   
```nano /etc/systemd/system/docker.service.d/http-proxy.conf```  
и заполняем  
```
[Service]
Environment="HTTP_PROXY=http://10.0.70.52:3128"
Environment="HTTPS_PROXY=http://10.0.70.52:3128"
```
После чего перезапускаем демона и сам докер командами в указанном порядке  
```systemctl daemon-reload```  
```systemctl restart docker```  
```docker pull freeipa/freeipa-server:centos-8-4.8.4```
```mkdir -p /var/lib/ipa-data```
  
```nano /etc/default/grub ```  
```GRUB_CMDLINE_LINUX="quiet systemd.unified_cgroup_hierarchy=0```
Для применения изменений необходимо использовать команду  
```grub-mkconfig -o /boot/grub/grub.cfg```   
После чего необходимо перезагрузить машину  
Следующим шагом уже переходим к запуску контейнера с хранящейся там FreeIPA, в качестве параметров ключей, указывает имя, указываем доменную сеть, а так открываем все необходимые для работы порты, указываем путь и образ, разрешаем конфликт с IPv6. Все параметры показаны на рисунке   
```  
docker run --name freeipa-server -ti -h hq-srv.hq.work -p 80:80 -p 443:443 -p 389:389 -p 636:636 -p 88:88 -p 464:464 -p 88:88/udp -p 464:464/udp -p 123:123/udp --read-only --sysctl net. ipv6.conf.all.disable_ipv6=0 -v /sys/fs/cgroup:/sys/fs/cgroup:rw -v /var/lib/ipa-data:/data:Z freeipa/freeipa-server: centos-8-4.8.4  
```
Важное Примечание:  
В случае завершения выполняемых функций в контейнере в результате которых оболочка может перейти в состояние freezing, или при успешном завершении, для выхода из оболочки окружения необходимо последовательно нажать сочетание клавиш ```ctrl + p```, а затем ```ctrl + q```. В случае если вам необходимо остановить контейнер можно воспользоваться командой ```docker stop``` имя контейнера, для удаления контейнера ```docker rm имя контейнера```, для просмотра существующих образов ```docker images```  
После успешного запуска необходимо заполнить форму:  
На вопрос о интеграции DNS нажимаем Enter  
На вопрос о задании имени сервера нажимаем Enter  
На вопрос о подтверждение имени домена нажимаем Enter  
На вопрос о подтверждение имени области нажимаем Enter  
На запрос ввода пароля для менеджера директорий вводим P@ssw0rd  
На запрос ввода пароля для IPA админа вводим P@ssw0rd  
На вопрос синхронизации с службой Chrony нажимаем Enter  
На вопрос о конфигурирование системы с текущими параметрами вводим yes  
Процесс установки достаточно длительный и может занимать около 5-10 или более минут.  
После завершения установки необходимо подготовить машины, которые будут присоединены к домену.  
Для этого первым делом переходим по пути:  
```Nano /etc/hosts```  
и пишем:  
для CLI  
```
127.0.0.1      localhost  
127.0.1.1      cli.hq.work      cli  
  
192.168.1.2 hq-srv.hq.work  
```
для BRSRV
```
127.0.0.1      localhost
127.0.1.1      br-srv.branch.work    br-srv

192. 168.1.2   hq-srv.hq.work
```
Следующим шагом посредством команды:  
```apt install freeipa-client```  
Производим установку клиентской части FreeIPA для ввода машины в домен.  
На все всплывающие окна во время установки нажимаем Enter  
После установки клиента, для ввода машины в домен необходимо прописать команды:   
НА CLI  
```ipa-client-install --mkhomedir --domain hq.work --server=hq-srv.hq.work -p admin -W```  
НА BR-SRV  
```ipa-client-install --mkhomedir --domain branch.work --server=hq-srv.hq.work -p admin -W```  
На сообщение о продолжении с фиксированными значения пишем yes  
На вопрос о конфигурирование CHRONY нажимаем ENTER  
На вопрос о конфигурировании с текущими значение пишем yes  
Для проверки входа в FreeIPA, на клиентской машине необходимо открыть браузер и в адресной строке написать IP адрес машины HQ-SRV (192.168.1.2) логин и пароль для входа в вебку FreeIPA: admin и P@ssw0rd  
Важное Примечание: если вы перезагрузите машину, то контейнер выключится, для его запуска можно воспользоваться командой  ```docker start freeipa-server```  
# 6 HQ-SRV Запустите сервис MediaWiki используя docker на сервере HQ-SRV  
Первым шагом необходимо установить docker compose, так как сам докер устанавливался в задании №3 второго модуля.  
Для этого посредством команды, показанной на рисунке ниже, скачаем необходимый пакет.  
```curl -L "https://github.com/docker/compose/releases/download/v2.18.1/docker-compose-$ (uname -s) -$(uname -m) -o /usr/local/bin/docker-compose```  
Командой, указанной на рисунке ниже, выдаём необходимые права для скаченной службы  
```chmod +x /usr/local/bin/docker-compose```  
Далее для того, чтобы с нуля не писать yml файл, можно скачать похожий по смыслу файл, приведённый на рисунке ниже (если будет запрещено, будете писать сами)  
```wget -L "https://raw.githubusercontent.com/pirate/wikipedia-mirror/master/docker-compose.mediawiki.yml" -0 /home/admin/wiki.yml```  
После чего открываем скачанный файл по пути  
```Nano /home/admin/wiki.yml```  
И приводим к виду, указанному на рисунке ниже, не удаляя присутст-вующие на рисунке закоменченные строки ! Соблюдая расстановку пробелов ! Заголовки первого порядка (Нажимаем один TAB или 2 пробела) , Второго порядка (2 TAB или 4 пробела), Третьего порядка (3 TAB или 6 пробелов).  
```
version: '3'
services:
  db:
    image: mysql
    environment:
      MYSQL_DATABASE: mediawiki
      MYSQL_USER: wiki
      MYSQL_PASSWORD: DEP@ssw0rd
      MYSQL_ROOT_PASSWORD: DEP@ssw0rd
    ports:
      - 3306:3306
    volumes:
      - /home/admin/dbvolume

  wiki:
    image: mediawiki
    ports:
      - 8080:80
#    volumes:
#      - /home/admin/LocalSettings.php:/var/www/html/LocalSettings.php
```
После чего запускаем контейнеры посредством команды  
```docker-compose -f /home/admin/wiki.yml up```  
После чего начнётся загрузка служб, после загрузки необходимо дождаться запуска контейнеров с сообщением о готовности подключения  
Далее необходимо перейти на машину CLI , и в браузере перейти по адре-су  192.168.1.2:8080  
Перейди по ссылке необходимо нажать → Continue  
Затем внизу страницы снова → Continue  
Далее на следующей странице необходимо указать настройки по заданию , как указано на рисунке ниже. Пароль DEP@ssw0rd  
---  
host-db  
name-mediawiki  
user-wiki  
пароль-DEP@ssw0rd  
Далее на следующей странице, заполняем поля как указано на рисунке ниже, обязательно не забыв поставить галочку о том что вы очень занятой внизу  
name-wiki   
proj-wiki  
user-Admin  
пароль-DEP@ssw0rd  
После чего сконфигурированный файл автоматически будет скачен в за-грузки  
Далее его необходимо перенести на сервер. Если вы выполнили задание с запретом доступа по SSH с машины CLI, файл необходимо будет кидать не на-прямую а через промежуточную машину HQ-R  
Для этого воспользовавшись командами  
На машине CLI от юзера админ (У вас может быть другой пользова-тель в зависимости от кого вы авторизировались в систему):  
```scp /home/admin/Downloads/LocalSettings.php root@192.168.1.1:/home/admin```  
На машине HQ-R:  
```scp /home/admin/LocalSettings.php admin@192.168.1.2:/home/admin/```  
После чего необходимо на машине HQ-SRV перейти по пути  
```nano /home/admin/wiki.yml```  
И раскоментить и переписать (если они у вас отличаются) строки указанные на рисунке ниже  
```
volumes:
  - /home/admin/LocalSettings.php:/var/www/html/LocalSettings.php
```
После чего снова запустить контейнеры.  
И теперь перейдя на машину CLI и зайдя в браузере по тому же адресу. Должна загрузится главная страница MediaWiki  
