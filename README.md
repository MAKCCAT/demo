# *****************Module_1*****************
# 1 ALL (Name/IPv4/IPv6)  
Если в задании не будут использоваться встроенные репозитории, а будет возможность скачивать все пакеты из интернета, необходимо отключить проверку пакетов через cdrom зайдя по пути Nano /etc/apt/sources.list и Закоментировать находящуюся там строку.  
### Name   
```
hostnamectl set-hostname Имя устройства  
Newgrp
```
### IP
|Name|Ipv4|mask|Def_get|Ipv6/mask|Def_getv6|
|---|---|---|---|---|---|
|CLI-ISP|192.168.0.2|255.255.255.0|192.168.0.1|2001::3:2/120|2001::3:1/120|!
|CLI-HQR|-|-|-|-|-|
|ISP-ClI|192.168.0.1|255.255.255.0|-|2001::3:1/120|-|
|ISP-HQR|10.10.10.2|255.255.255.252|-|2001::7:2/126|-| 
|ISP-BRR|10.10.10.6|255.255.255.252|-|2001::7:6/126|-|
|HQR-HQSRV|192.168.1.1|255.255.255.192|-|2001::1:1/122|-| 
|HQR-ISP|10.10.10.1|255.255.255.252|-|2001::7:1/126|-|
|HQR-CLI|-|-|-|-|-|
|HQSRV-HQR|192.168.1.2|255.255.255.192|192.168.1.1|2001::1:2/122|2001::1:1/122|
|BRR-BRSRV|192.168.2.1|255.255.255.240|-|2001::2:1/124|-|
|BRR- ISP|10.10.10.5|255.255.255.252|-|2001::7:5/126|-|
|BRSRV-BRR|192.168.2.2|255.255.255.240|10.10.10.5|2001::2:2/124|2001::2:1/124|
---
![maskv4](https://myeditor.ru/wp-content/uploads/b/8/3/b83c1b85ee91682121df78aca1e4576f.png)  
```
Ip a  
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
изменить параметры на YES для протокола ospfd и ospf6d  
### Настройка OSPF v4
```
Vtysh 
Conf t  
router ospf 
```
|Name|id|network|area|
|---|---|---|---|
|BRR-ISP|2.2.2.2|10.10.10.4/30|0|
|BRR-BRSRV|2.2.2.2|192.168.2.0/28|2| 
|HQR-ISP|3.3.3.3|10.10.10.0/30|0|
|HQR-HQRSRV|3.3.3.3|192.168.1.0/26|3|
|ISP-BRR|4.4.4.4|10.10.10.4/30|0| 
|ISP-HQR|4.4.4.4|10.10.10.0/30|0| 
|ISP-CLI|4.4.4.4|192.168.3.0/24|4|
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
переменную ```net.ipv4.ip_forward=1``` и ```net.ipv6.conf.all.forwarding=1``` необходимо раскоментить и сохранинть измнения в файле, и применить изменения командой
```sysctl –p ```  
```diff
-При каждой перезагрузки прописывать sysctl –p 
```  
### Настройка OSPF v6
```
Vtysh
Conf t  
router ospf6  
```
|Name|id|area|range/mask|
|---|---|---|---|
|BRR-ISP|0.0.0.2|0.0.0.0|2001::7:4/126|
|BRR-BRSRV|0.0.0.2|0.0.0.0|2001::2:0/124| 
|HQR-ISP|0.0.0.3|0.0.0.0|2001::7:0/126|
|HQR-HQRSRV|0.0.0.3|0.0.0.0|2001::1:0/122|
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
---
### IPv4
``` nano /etc/dhcp/dhcpd.conf ```  
Пример DHCP для ipv4 без Relay:  
```
default-lease-time 600;  
max-lease-time 7200;  
ddns-updates on;  
ddns-update-style interim;  
authoritative;
  
subnet 192.168. 1.0 netmask 255.255.255. 192 {
 range 192. 168.1.3 192.168.1.62;
 option routers 192.168.1.1;
 option domain-name "hq.work";
 option domain-name-servers 192.168.1.2;
}
```  
Где:  
```ddns-update-style interim``` — способ автообновления базы dns  
```authoritative``` — делает сервер доверенным  
```subnet``` — указание сети  
```range — пул адресов```  
```option routers — шлюз по умолчанию```  
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
2) Расширеный вариант:
```
#!/bin/bash
backup_files="/home /etc /root /boot /opt"

dest="/mnt/backup"

day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

tar czf $dest/sarchive_file $backup_files

echo
echo "Backup finished"
date

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
# 7 HQ-SRV (SSH по порту 2222, средства контролирования трафика)  
```nano /etc/ssh/sshd_config```  
Изменяем порт на 2222  
```systemctl restart ssh```  
```apt install iptables-persistent```  
правило iptables для подмены порта ssh:  
```iptables -t nat -A PREROUTING -d 192.168.1.2/26 -p tcp -m tcp --dport -destination 192.168.1.2:2222```  
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
# *****************Module_2*****************  
# 1  HQ-SRV (DNS Server)  
### Зона hq.work
|HQ-R.hq.work|A,PTR|IP - адрес|
|---|---|---|
|HQ-SRV.hq.work|A,PTR|IP - адрес|
---  
### Зона branch.work
|BR-R.branch.work|A,PTR|IP - адрес|
|---|---|---|
|BR-SRV.branch.work|A|IP - адрес|
---  
```apt install bind9 dnsutils```  
---  
```nano /etc/bind/named.conf.default-zones```  
---  
Зоны для hq.work:  
```  
zone "hq. work" {  
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
zone
"0.0.0.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa" { type master: file ". "/etc/bind/hq6_arpa";
allow-update fany;};``  
```  
---  
где:  
zone — создаваемая зона  
type — выбор между первичным и вторичным dns. (Master и Slave)  
file — расположение конфигурационного файла зоны  
allow-update — разрешение динамических обновлений  
где zone:  
hq.work — зона прямого просмотра  
in-addr.arpa — зона обратного просмотра ipv4  
ip6.arpa — зона обратного просмотра ipv6 (указывается полностью. В обратном порядке)  
---  
Зоны для branch.work:  
```
zone "branch. work" {  
  type master;  
  file "/etc/bind/branch";  
  allow-update {any;};  
  allow-transfer {any;};  
};  
  
zone "2.168.192.in-addr.arpa" {  
  type master;  
  file "/etc/bind/branch_arpa";  
  allow-update {any:};
};
  
zone "0.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.0.2.ip6.arpa" {  
  type master;  
  file "/etc/bind/branch6_arpa";  
  allow-update {any;};
};  
```  
