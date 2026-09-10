# Host firewall hardening plan — M1

> Publication redaction: workstation-specific evidence/settings were withheld. Methods, dated outcomes and limitations remain historical; omitted values are not replacement measurements.

Historical firewall change plan: review → backup → approval → apply → verification → rollback. Exact target policy and native output are withheld.

## CURRENT STATE
[Publication redaction: private workstation observation/configuration omitted.]

## THREAT MODEL RELEVANCE

Цель — уменьшить риск случайного открытия developer service соседям по LAN или
на будущих routable interfaces. Компрометация LAN/router или ошибочный bind не должны
автоматически давать доступ к новому host server. Это относится к F03, но не закрывает
F01: доступ malicious user process к rootful Docker socket.

Host firewall не исправляет supply-chain compromise, украденные credentials,
malware в пользовательской сессии, отсутствие disk encryption или backup.
Outbound exfiltration этой политикой не блокируется.

## TARGET POLICY
[Publication redaction: private workstation observation/configuration omitted.]

## EXACT PROPOSED COMMANDS
[Publication redaction: private workstation observation/configuration omitted.]

## EXPECTED RESULT
[Publication redaction: private workstation observation/configuration omitted.]

Listeners не должны исчезать или менять bind: firewall контролирует packets,
а не запускает/останавливает приложения. CUPS/containerd/Cursor остаются loopback.
UFW status не показывает все before/after rules, поэтому одного Status active мало.
Никаких заявлений о проверенной WAN защите до независимых evidence.

## DOCKER INTERACTION
[Publication redaction: private workstation observation/configuration omitted.]

## IPv4 / IPv6 BEHAVIOR
[Publication redaction: private workstation observation/configuration omitted.]

## COMPATIBILITY RISKS

- **DHCP/NetworkManager:** IP lease renewal зависит от client reply exceptions.
  Не переподключать interface и не принудительно renew lease ради этого increment.
- **DNS:** loopback stub и outbound DNS должны работать; широкое inbound allow 53
  не нужно. Проверять разрешение нового имени, не только наличие resolver process.
- **Avahi/mDNS:** поведение зависит от рабочей before policy; optional decision выше.
- **CUPS:** localhost TCP 631 должен сохраниться. Поиск сетевых printers и печать
  на них — отдельные flows; их успех не следует из доступности localhost CUPS.
- **VPN/OpenVPN:** сейчас server не нужен. Будущий outbound client обычно использует
  stateful replies, но tunnel routes, forwarded traffic и protocol exceptions
  требуют review; не создавать inbound VPN allow заранее.
- **Docker:** изменение builtin FORWARD policy/jump ordering может нарушить networking;
  static checks при stopped containers не докажут runtime connectivity.
- **Localhost development:** сохранить IPv4/IPv6 loopback. Будущий wildcard service
  не разрешается автоматически; host firewall не ограничивает другие local processes.
- **Будущий LAN dashboard:** потребует собственного правила и authentication review.
  Не открывать весь LAN для всех ports и не добавлять permanent 3000/8000/5432 allow.

## PRE-CHANGE CHECKS
[Publication redaction: private workstation observation/configuration omitted.]

## VERIFICATION PLAN


Только для будущего согласованного окна; команды здесь сейчас не выполнялись.
После каждой изменяющей команды проверить результат; итоговая проверка включает:

**UFW и effective state, read-only с отдельным approval:**

[Publication redaction: native command/output block withheld.]

[Publication redaction: private workstation observation/configuration omitted.]



**Listeners, addresses, routes и DNS configuration:**

[Publication redaction: native command/output block withheld.]

Bind не должен измениться; не создавать listener специально для теста. Нуждающиеся
в sudo ownership fields читаются только после отдельного согласования.

**Connectivity — отдельные согласуемые активные проверки:**

[Publication redaction: native command/output block withheld.]

Использовать уже установленный curl; ничего не устанавливать. HTTP response от CUPS,
в том числе auth-related status, подтверждает transport connectivity; refused/timeout
сравнивать с исходным состоянием. Не отправлять HTTP на containerd internal port.
HTTPS проверяет outbound TCP/TLS и responses; не отменять certificate validation.
Эти запросы создают трафик и могут обновлять DNS cache/access logs, поэтому не входят
в текущий разрешённый filesystem-only inspection.

Для IPv6 при наличии global address и default route выполнить отдельно согласованный
аналог с `curl -6` к тому же HTTPS endpoint. Пока их нет, отметить external IPv6
connectivity **UNKNOWN / не проверено**, проверить IPv6 loopback и rules статически.
Не включать IPv6 forwarding, не добавлять route и не отключать IPv6 ради теста.
Lease renewal, VPN и реальную печать проверять при естественном использовании либо
в отдельном согласованном compatibility test, не restart NetworkManager/services.

**Docker без тестового запуска:** после отдельного разрешения на read-only API reads
повторить inventory только state/network/ports/security fields и сравнить с pre-change.
Ожидать те же stopped containers, сохранённые networks и publications; env values
не выводить. Не запускать hello-world, compose up, exec или restart Docker.
Это подтверждает сохранение структуры, но runtime NAT/connectivity остаются
непроверенными до легитимного отдельно согласованного запуска workloads.

**Будущая LAN verification:** если понадобится, согласовать второе принадлежащее
владельцу устройство, interface и конкретные адреса/ports. Проверить denied host
flows и только одобренные exceptions. Отсутствие listener нельзя засчитывать как
доказательство firewall block; создание synthetic listener требует отдельного approval.
Для IPv6 использовать реальный link-local/global контекст, где применимо.
WAN/router verification — отдельная работа, не вывод из LAN test или INPUT policy.

## ROLLBACK PLAN
[Publication redaction: private workstation observation/configuration omitted.]

## KNOWN LIMITATIONS
[Publication redaction: private workstation observation/configuration omitted.]

## APPROVAL BOUNDARY

Этот документ разрешает **только review**, не выполнение. В будущих отдельных approval
должны быть явно указаны exact commands, эффект, риск, verification и rollback:

1. **Текущий запрос на approval:** только ручной read-only batch ниже. Он не
   содержит restore --test, backup writes или ufw mutations. Дополнительные reads
   custom hook snippets требуют отдельного review с удалением чувствительных literals.
   Будущий restore `--test` согласуется отдельно.
2. **Backup write:** install каталога, cp файлов, tee snapshots по приведённым путям.
   Это запись вне repo и требует approval, несмотря на отсутствие изменения policy.
3. **Apply отдельно от preflight:** только `ufw enable` при верных defaults, включая
   IPv6 FORWARD DROP, boot persistence, возможные sysctl effects и проверенные hooks.
   Команды `ufw default` — лишь отдельные conditional corrections при drift.
   Новые service allows и изменения before rules не входят в это approval.
4. **Verification traffic:** локальные HTTP, DNS/HTTPS и будущие LAN/IPv6 probes;
   только согласованные endpoints. Docker reads согласуются без права запуска workload.
5. **Rollback:** `ufw disable`, обе `iptables-restore`/`ip6tables-restore` без --test,
   `sysctl -p` и восстановительные cp из этого документа — отдельные system-changing
   операции. Лучше согласовать их условное выполнение при failure до apply.

Любые новые rule edits, packages, Docker changes, services, sysctls вне описанных
effects требуют нового конкретного плана. Нет разрешения на M2 или autonomous remediation.

## Проверенные источники

Дата проверки: 2026-09-10. Локальные файлы читались как данные, не выполнялись:
`/etc/default/ufw`, `/etc/ufw/ufw.conf`, `/etc/ufw/sysctl.conf`,
`/usr/share/ufw/iptables/{before,before6,after,after6}.rules`,
`/lib/ufw/ufw-init-functions`; локальные man pages ufw, ufw-framework, iptables-restore.
Названия поведения и команды сопоставлены с установленным UFW и Ubuntu jammy.

- [Ubuntu jammy: UFW](https://manpages.ubuntu.com/manpages/jammy/man8/ufw.8.html).
- [Ubuntu jammy: UFW framework](https://manpages.ubuntu.com/manpages/jammy/man8/ufw-framework.8.html).
- [Docker firewall interaction](https://docs.docker.com/engine/network/packet-filtering-firewalls/).
- [Docker port publishing](https://docs.docker.com/engine/network/port-publishing/).

**NO SYSTEM CHANGES WERE MADE.** Изменён только этот документ, commit не выполнялся.
