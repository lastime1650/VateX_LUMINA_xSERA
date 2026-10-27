# Host isolation qualification boundaries

The actual Linux run16 proved IPv4 fresh TCP and an already established TCP
connection were denied, exact SSH/TLS management remained usable, manual release
restored access, and an independent 30-second watchdog released isolation after
the Agent stopped. These are actual OS effects, distinct from the 1,000 explicitly
synthetic benign endpoint/FortiGate records. Native procfs, auditd and trusted
sshd-session records supplied the genuine endpoint evidence.

Remote IPv6 management endpoints are rejected before a durable receipt, watchdog
or native firewall mutation is created. The existing isolation rules deny
non-TCP traffic and do not implement qualified IPv6 Neighbor Discovery or Path
MTU Discovery handling. An immediately successful connection with a cached
neighbor is insufficient proof that management will remain reachable. Netfilter
documents the need for Neighbor Discovery exceptions to preserve IPv6
connectivity: [official nftables workstation example](https://wiki.nftables.org/wiki-nftables/index.php/Simple_ruleset_for_a_workstation).
IPv6 loopback `::1` is local IPC and remains permitted; this does not qualify
remote IPv6 management. Previously created receipts must still be removable.

Linux management permits now bind conntrack direction as well as the exact IP
and TCP service port. Original service-direction packets allow tracked new or
established connections; reverse packets must be established replies. This
prevents both new and already-established inverse connections from gaining an
exception by reusing an approved source port. The filter hooks run at priority0,
after conntrack priority-200. There is no blanket permit for established traffic.
See the [official Netfilter hook ordering](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks).
Native run16 predates this correction and does not qualify the new predicate;
fresh namespace packet evidence is required.

The original Windows 0.10 planner combined complementary local and remote TCP
port fields in each block rule. An opposite-direction source port could therefore
miss the intended block at an approved management IP. The correction restricts
inbound local service ports and outbound remote service ports independently.
Planner and unit checks do not prove actual Windows packet effects or return-flow
availability. The original native run4 qualifies its recorded old predicate;
fresh denial and management-return-flow evidence is required for the correction.

The next meaningful network experiment belongs in an explicitly disposable
Linux network namespace or VM. It must establish allowed management from a
fresh IPv6 neighbor state, refresh that state during isolation, exercise a
routed path with a smaller MTU, and check unrelated IPv4/IPv6 TCP, UDP, DNS and
ICMP before isolation, while isolated and after release. The peer must record
fresh nonces so an unrelated timeout or stale reply cannot be counted as a
successful block. No broad NDP/ICMP allow rule should be inferred from the
existing IPv4 result.

The existing watchdog result proves Agent-stop recovery while the independent
guard continues running. Guard termination with the Agent alive is covered by
local recovery contracts; an additional real failure-injection experiment would
test the OS effect and management restoration within the control-cycle budget.
Simultaneous Agent/guard termination, hard power loss, restart ordering, native
firewall persistence and long clock discontinuities are separate qualifications.
The guard cannot execute cleanup while every recovery process is dead. Linux
kernel tables and Windows persistent firewall/App Control policies have
different reboot behavior and must be assessed in expendable hosts, not by
rebooting an operating console to strengthen a report.

Linux fanotify prevention covers executable opens of immediate children in
explicit protected directories. Interpreter input prevention, queue-overflow
coverage, listener-death behavior and fleet-wide kernel compatibility are not
certified by the harmless exact-hash pre-main denial. Listener death releases
outstanding kernel permission requests; the reported state must remain honest.
Polling process/TCP collection does not prove lossless short-lived process
capture. Native service installation, reboot persistence, extended loss/soak,
physical FortiGate appliances and broad commercial fleet support require their
own evidence. The retained 2,246-test pass is the original frozen release's
contract result; any later source correction requires a separately identified
validation result.
