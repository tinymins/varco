#!/usr/bin/env bash
# End-to-end test with real TUN devices: one server, four clients, two networks.
# Needs only Docker. Usage: tests/e2e/run.sh
set -uo pipefail
cd "$(dirname "$0")/../.."

NET=varco-e2e; IMG=varco-e2e; VOL=varco-e2e-target; PORT=8443
# s1 has no TUN access at all: it proves SSH-only mode needs none.
NODES=(srv a1 a2 a3 b1 s1)
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS  $1"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
check() { local name=$1; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }
refuse() { local name=$1; shift; if "$@" >/dev/null 2>&1; then bad "$name"; else ok "$name"; fi; }
ex() { docker exec "varco-$1" bash -c "$2"; }

cleanup() {
  for n in "${NODES[@]}"; do docker rm -f "varco-$n" >/dev/null 2>&1; done
  docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
cleanup

docker build -q -t "$IMG" tests/e2e >/dev/null || exit 2
docker volume create "$VOL" >/dev/null
echo "== build"
docker run --rm -v "$PWD:/src:ro" -v "$VOL:/target" -w /src -e CARGO_TARGET_DIR=/target "$IMG" \
  cargo build --locked --bin varco 2>&1 | tail -1
[ "${PIPESTATUS[0]}" = 0 ] || exit 2

docker network create "$NET" >/dev/null
for n in "${NODES[@]}"; do
  tun=(--cap-add NET_ADMIN --device /dev/net/tun)
  [ "$n" = s1 ] && tun=()
  docker run -d --name "varco-$n" --hostname "$n" --network "$NET" \
    ${tun[@]+"${tun[@]}"} -v "$VOL:/target:ro" \
    "$IMG" sleep infinity >/dev/null
done
docker exec -i varco-srv bash -c 'mkdir -p /etc/varco && cat > /etc/varco/config.toml' <<CFG
listen = "0.0.0.0:$PORT"
public_addr = "varco-srv:$PORT"
[[network]]
name = "a"
cidr = "10.77.1.0/24"
[[network]]
name = "b"
cidr = "10.77.2.0/24"
CFG

BIN=/target/debug/varco
gen() { ex srv "$BIN server gen-credential --network $1"; }
OUT_A=$(gen a); OUT_B=$(gen b)
secret() { echo "$1" | sed -n 2p | tr -d ' "'; }
code()   { echo "$1" | sed -n 4p | tr -d ' '; }
CODE_A=$(code "$OUT_A"); CODE_B=$(code "$OUT_B")
ex srv "sed -i '/name = \"a\"/a credentials = [\"$(secret "$OUT_A")\"]' /etc/varco/config.toml
        sed -i '/name = \"b\"/a credentials = [\"$(secret "$OUT_B")\"]' /etc/varco/config.toml"

start_server() { docker exec -d varco-srv bash -c "$BIN server -c /etc/varco/config.toml >>/tmp/server.log 2>&1"; }
stop_server()  { ex srv "pkill -x varco"; }
join() { docker exec -d -e "VARCO_CREDENTIAL=$2" "varco-$1" bash -c "$BIN >>/tmp/client.log 2>&1"; }
mesh_ip() { ex "$1" "ip -4 -o addr | awk '\$2!=\"lo\" && \$2!=\"eth0\" {print \$4}' | cut -d/ -f1 | head -1"; }
wait_ip() { for _ in $(seq 60); do local ip; ip=$(mesh_ip "$1"); [ -n "$ip" ] && { echo "$ip"; return 0; }; sleep 0.5; done; return 1; }
ping1() { ex "$1" "ping -c1 -W2 $2"; }
wait_ping() { for _ in $(seq "${3:-60}"); do ping1 "$1" "$2" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

start_server; sleep 1
echo "== join"
join a1 "$CODE_A"; join a2 "$CODE_A"; join a3 "$CODE_A"; join b1 "$CODE_B"
IP_A1=$(wait_ip a1); IP_A2=$(wait_ip a2); IP_A3=$(wait_ip a3); IP_B1=$(wait_ip b1)
echo "  a1=$IP_A1 a2=$IP_A2 a3=$IP_A3 b1=$IP_B1"
[ -n "$IP_A1" ] && [ -n "$IP_A2" ] && [ -n "$IP_A3" ] && [ -n "$IP_B1" ] || { ex a1 'cat /tmp/client.log'; ex srv 'cat /tmp/server.log'; exit 1; }

echo "== reachability"
check  "a1 -> a2 same network"           wait_ping a1 "$IP_A2" 10
check  "a2 -> a1 same network"           ping1 a2 "$IP_A1"
refuse "a1 -> b1 across networks"        ping1 a1 "$IP_B1"
refuse "b1 -> a1 across networks"        ping1 b1 "$IP_A1"
refuse "a1 -> unassigned host in subnet" ping1 a1 10.77.1.200

echo "== nothing beyond the mesh"
ROUTES=$(ex a1 "ip route")
check  "default route still via eth0" bash -c "echo '$ROUTES' | grep -q '^default .* dev eth0'"
TUN_DEV=$(ex a1 "ip -4 -o addr | awk '\$2!=\"lo\" && \$2!=\"eth0\" {print \$2}' | head -1")
check  "only the mesh subnet uses the TUN" bash -c "[ \"\$(echo '$ROUTES' | grep -c 'dev $TUN_DEV')\" = 1 ] && echo '$ROUTES' | grep -q '^10.77.1.0/24 .*dev $TUN_DEV'"
SRV_ETH=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' varco-srv)
refuse "server has no TUN or mesh address" ex srv "ip -4 -o addr | grep -q 10.77"
# Force traffic for the server and the Internet into the TUN, as a hostile client would.
ex a1 "ip route add 8.8.8.8/32 dev $TUN_DEV; ip route add $SRV_ETH/32 dev $TUN_DEV"
refuse "forced via TUN: Internet unreachable" ping1 a1 8.8.8.8
refuse "forced via TUN: server unreachable"   ping1 a1 "$SRV_ETH"
ex a1 "ip route del 8.8.8.8/32; ip route del $SRV_ETH/32"

echo "== rejected joins (run in b1 as a one-off process, which must exit by itself)"
attempt() { docker exec -e "VARCO_CREDENTIAL=$1" varco-b1 timeout 20 "$BIN" 2>&1; }
expect_msg() { local name=$1 code=$2 pattern=$3; local out; out=$(attempt "$code"); local rc=$?
  if [ "$rc" = 1 ] && echo "$out" | grep -q "$pattern"; then ok "$name"; else bad "$name (rc=$rc: $out)"; fi; }
# Issued for network a but never added to the config.
UNLISTED=$(code "$(gen a)")
expect_msg "unlisted secret is rejected"   "$UNLISTED" "无效或已被撤销"
expect_msg "malformed code is rejected"    "garbage"   "格式不正确"
# A different server key gives a valid code whose pin does not match this server.
ex srv "mkdir -p /tmp/other && cp /etc/varco/config.toml /tmp/other/config.toml"
WRONG_PIN=$(code "$(ex srv "$BIN server -c /tmp/other/config.toml gen-credential --network a")")
expect_msg "wrong pin (simulated MITM) is rejected" "$WRONG_PIN" "证书与 Code 不符"
REFUSED=$(ex srv "grep -c 'connection rejected' /tmp/server.log")
[ "$REFUSED" = 1 ] && ok "only the unlisted secret reached the server's auth step" \
                   || bad "expected 1 auth rejection, got $REFUSED"

echo "== inner TCP survives a 60 s outage"
ex a1 "head -c 12000000 /dev/urandom > /tmp/blob; sha256sum < /tmp/blob > /tmp/blob.sum"
docker exec -d varco-a2 bash -c "nc -l -p 9000 > /tmp/recv"
sleep 1
# 100 kB/s, so the transfer spans the whole outage.
docker exec -d varco-a1 bash -c "pv -q -L 100k /tmp/blob | nc -N $IP_A2 9000; touch /tmp/sent"
sleep 10
ex a1 "iptables -A OUTPUT -p tcp --dport $PORT -j DROP"
sleep 60
SENT_BEFORE=$(ex a2 "stat -c %s /tmp/recv")
ex a1 "iptables -D OUTPUT -p tcp --dport $PORT -j DROP"
check  "client log shows it noticed the outage" ex a1 "grep -q '重连\|session ended' /tmp/client.log"
check  "a1 rejoined after the outage"      wait_ping a1 "$IP_A2" 60
check  "a1 kept its address"               ex a1 "ip -4 -o addr | grep -q ' $IP_A1/'"
for _ in $(seq 400); do ex a1 "test -f /tmp/sent" 2>/dev/null && break; sleep 1; done
sleep 2
if [ "$(ex a2 'sha256sum < /tmp/recv')" = "$(ex a1 'cat /tmp/blob.sum')" ]; then
  ok "12 MB transfer intact across the outage (paused at $SENT_BEFORE bytes)"
else
  bad "transfer corrupted or incomplete: $(ex a2 'stat -c %s /tmp/recv') of 12000000 bytes"
fi

echo "== server restart"
stop_server; sleep 2; start_server
check  "a1 -> a2 after restart"            wait_ping a1 "$IP_A2" 60
check  "a1 address unchanged"              ex a1 "ip -4 -o addr | grep -q ' $IP_A1/'"
check  "a2 address unchanged"              ex a2 "ip -4 -o addr | grep -q ' $IP_A2/'"
refuse "code still valid after restart (key kept)" ex a1 "grep -q '无效或已被撤销' /tmp/client.log"

echo "== a stuck client does not affect others"
ex a2 "pkill -STOP -x varco"
# Keep sending to the frozen member so its queue on the server is full.
docker exec -d varco-a1 bash -c "timeout 20 ping -i 0.01 -s 1000 $IP_A2 >/dev/null 2>&1"
sleep 5
check  "a1 -> a3 works while a2 is frozen and flooded" ping1 a1 "$IP_A3"
check  "a3 -> a1 works while a2 is frozen and flooded" ping1 a3 "$IP_A1"
sleep 16
ex a2 "pkill -CONT -x varco"
check  "a2 recovers after being resumed"   wait_ping a2 "$IP_A1" 90
check  "a2 address unchanged"              ex a2 "ip -4 -o addr | grep -q ' $IP_A2/'"

echo "== 5% packet loss on the outer link"
if ex a1 "tc qdisc add dev eth0 root netem loss 5%" 2>/dev/null; then
  ex a1 "head -c 2000000 /dev/urandom > /tmp/blob2; sha256sum < /tmp/blob2 > /tmp/blob2.sum; rm -f /tmp/sent2"
  docker exec -d varco-a3 bash -c "nc -l -p 9001 > /tmp/recv2"
  sleep 1
  docker exec -d varco-a1 bash -c "nc -N $IP_A3 9001 < /tmp/blob2; touch /tmp/sent2"
  for _ in $(seq 180); do ex a1 "test -f /tmp/sent2" 2>/dev/null && break; sleep 1; done
  sleep 2
  ex a1 "tc qdisc del dev eth0 root"
  if [ "$(ex a3 'sha256sum < /tmp/recv2')" = "$(ex a1 'cat /tmp/blob2.sum')" ]; then
    ok "2 MB transfer intact under 5% loss"
  else
    bad "transfer under loss incomplete: $(ex a3 'stat -c %s /tmp/recv2') of 2000000 bytes"
  fi
else
  echo "  SKIP  netem not available in this kernel"
fi

echo "== built-in SSH server"
SSH_PORT=2222
check_closed() { ex "$1" "! nc -z -w3 $2 $SSH_PORT"; }
check  "off by default: nothing listens on $SSH_PORT" check_closed a1 "$IP_A2"
ex a1 "ssh-keygen -q -t ed25519 -N '' -f /tmp/id; ssh-keygen -q -t ed25519 -N '' -f /tmp/other"
PUBKEY=$(ex a1 "cat /tmp/id.pub")
# a3 rejoins as an SSH server; a1 is the client.
ex a3 "pkill -x varco; true"
sleep 2
docker exec -d -e "VARCO_CREDENTIAL=$CODE_A" -e "VARCO_SSH_PUBKEY=$PUBKEY" varco-a3 bash -c "$BIN >>/tmp/client-ssh.log 2>&1"
IP_S=""
for _ in $(seq 60); do IP_S=$(mesh_ip a3); [ -n "$IP_S" ] && ex a3 "grep -q 'SSH 已开启' /tmp/client-ssh.log" 2>/dev/null && break; sleep 0.5; done
echo "  ssh server a3=$IP_S"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o BatchMode=yes -o ConnectTimeout=8 -p $SSH_PORT"
sshq() { ex a1 "ssh -i /tmp/id $SSH_OPTS root@$IP_S $(printf '%q' "$1")"; }
if [ "$(sshq 'echo ok-$((6*7))')" = "ok-42" ]; then ok "ssh with the right key runs a command"; else bad "ssh command failed"; ex a3 "tail -5 /tmp/client-ssh.log"; fi
[ "$(sshq 'exit 7' >/dev/null 2>&1; echo $?)" = 7 ] && ok "exit code comes back" || bad "exit code lost"
refuse "ssh with another key is refused" ex a1 "ssh -i /tmp/other -o IdentitiesOnly=yes $SSH_OPTS root@$IP_S true"
refuse "password login is not offered" ex a1 "ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no $SSH_OPTS root@$IP_S true"
check  "the code is not visible to remote commands" bash -c "! docker exec varco-a1 ssh -i /tmp/id $SSH_OPTS root@$IP_S env | grep -q VARCO_"
ex a1 "head -c 3000000 /dev/urandom > /tmp/scp-up; sha256sum < /tmp/scp-up > /tmp/scp-up.sum"
ex a1 "scp -i /tmp/id ${SSH_OPTS/-p $SSH_PORT/-P $SSH_PORT} /tmp/scp-up root@$IP_S:/tmp/scp-landed && scp -i /tmp/id ${SSH_OPTS/-p $SSH_PORT/-P $SSH_PORT} root@$IP_S:/tmp/scp-landed /tmp/scp-back" 2>&1 | tail -1
[ "$(ex a3 'sha256sum < /tmp/scp-landed' 2>/dev/null)" = "$(ex a1 'cat /tmp/scp-up.sum')" ] && [ "$(ex a1 'sha256sum < /tmp/scp-back' 2>/dev/null)" = "$(ex a1 'cat /tmp/scp-up.sum')" ] && ok "scp both ways, 3 MB intact" || bad "scp round trip differs"
docker exec -d varco-a3 bash -c "echo via-loopback | nc -l -p 9100 -s 127.0.0.1 -q1"
docker exec -d varco-a1 bash -c "ssh -i /tmp/id $SSH_OPTS -N -L 9101:127.0.0.1:9100 root@$IP_S"
sleep 2
[ "$(ex a1 'nc -w3 127.0.0.1 9101 </dev/null')" = "via-loopback" ] && ok "ssh -L reaches the machine's own loopback" || bad "ssh -L to loopback failed"
docker exec -d varco-a2 bash -c "echo leaked | nc -l -p 9102 -q1"
docker exec -d varco-a1 bash -c "ssh -i /tmp/id $SSH_OPTS -N -L 9103:$IP_A2:9102 root@$IP_S"
sleep 2
[ -z "$(ex a1 'nc -w3 127.0.0.1 9103 </dev/null' 2>/dev/null)" ] && ok "ssh -L to another address is refused" || bad "ssh -L reached another machine"
refuse "ssh -R is refused" ex a1 "ssh -i /tmp/id $SSH_OPTS -o ExitOnForwardFailure=yes -R 9200:127.0.0.1:22 root@$IP_S true"
check  "another network cannot reach the port" check_closed b1 "$IP_S"
A3_ETH=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' varco-a3)
check  "the machine's real address has no SSH" check_closed a1 "$A3_ETH"
docker exec -d varco-a1 bash -c "ssh -i /tmp/id $SSH_OPTS root@$IP_S 'sleep 75; echo survived' > /tmp/ssh-outage 2>&1"
sleep 5
ex a1 "iptables -A OUTPUT -p tcp --dport $PORT -j DROP"
sleep 60
ex a1 "iptables -D OUTPUT -p tcp --dport $PORT -j DROP"
for _ in $(seq 60); do ex a1 "grep -q survived /tmp/ssh-outage" 2>/dev/null && break; sleep 2; done
check  "an open SSH session survives a 60 s outage" ex a1 "grep -q survived /tmp/ssh-outage"
docker exec -d varco-a1 bash -c "ssh -i /tmp/id $SSH_OPTS root@$IP_S 'sleep 987'"
sleep 2
check  "a remote process is running" ex a3 "pgrep -f '[s]leep 987'"
ex a3 "pkill -INT -x varco"
sleep 3
refuse "leaving ends remote processes" ex a3 "pgrep -f '[s]leep 987'"

echo "== SSH-only mode: no virtual NIC"
refuse "refuses to start without a key" ex s1 "VARCO_CREDENTIAL=$CODE_A $BIN --ssh-only"
docker exec -d -e "VARCO_CREDENTIAL=$CODE_A" -e "VARCO_SSH_PUBKEY=$PUBKEY" varco-s1 bash -c "$BIN --ssh-only >>/tmp/client-ssh.log 2>&1"
IP_O=""
for _ in $(seq 60); do
  IP_O=$(ex s1 "sed -n 's/^SSH 已开启：\([0-9.]*\):.*/\1/p' /tmp/client-ssh.log | tail -1" 2>/dev/null)
  [ -n "$IP_O" ] && break
  sleep 0.5
done
echo "  ssh-only s1=$IP_O"
[ -n "$IP_O" ] || { bad "ssh-only client never came up"; ex s1 'cat /tmp/client-ssh.log'; }
[ -z "$(mesh_ip s1)" ] && ok "no network interface was added" || bad "an interface appeared"
sshz() { ex a1 "ssh -i /tmp/id $SSH_OPTS root@$IP_O $(printf '%q' "$1")"; }
SCP_OPTS="${SSH_OPTS/-p $SSH_PORT/-P $SSH_PORT}"
check  "answers ping" wait_ping a1 "$IP_O" 10
[ "$(sshz 'echo ok-$((6*7))')" = "ok-42" ] && ok "ssh with the right key runs a command" || bad "ssh command failed"
refuse "ssh with another key is refused" ex a1 "ssh -i /tmp/other -o IdentitiesOnly=yes $SSH_OPTS root@$IP_O true"
ex a1 "head -c 3000000 /dev/urandom > /tmp/only-up; sha256sum < /tmp/only-up > /tmp/only-up.sum"
ex a1 "scp -i /tmp/id $SCP_OPTS /tmp/only-up root@$IP_O:/tmp/only-landed && scp -i /tmp/id $SCP_OPTS root@$IP_O:/tmp/only-landed /tmp/only-back" 2>&1 | tail -1
[ "$(ex s1 'sha256sum < /tmp/only-landed' 2>/dev/null)" = "$(ex a1 'cat /tmp/only-up.sum')" ] && [ "$(ex a1 'sha256sum < /tmp/only-back' 2>/dev/null)" = "$(ex a1 'cat /tmp/only-up.sum')" ] && ok "scp both ways, 3 MB intact" || bad "scp round trip differs"
ex a1 "printf 'put /tmp/only-up /tmp/only-sftp\nbye\n' | sftp -q -i /tmp/id $SCP_OPTS -b - root@$IP_O" >/dev/null 2>&1
[ "$(ex s1 'sha256sum < /tmp/only-sftp' 2>/dev/null)" = "$(ex a1 'cat /tmp/only-up.sum')" ] && ok "sftp upload intact" || bad "sftp upload differs"
docker exec -d varco-s1 bash -c "echo via-loopback | nc -l -p 9100 -s 127.0.0.1 -q1"
docker exec -d varco-a1 bash -c "ssh -i /tmp/id $SSH_OPTS -N -L 9111:127.0.0.1:9100 root@$IP_O"
sleep 2
[ "$(ex a1 'nc -w3 127.0.0.1 9111 </dev/null')" = "via-loopback" ] && ok "ssh -L reaches the machine's own loopback" || bad "ssh -L to loopback failed"
docker exec -d varco-s1 bash -c "nc -l -p 9112 -k >/dev/null"
sleep 1
refuse "other ports stay closed, even with a listener behind them" ex a1 "nc -z -w3 $IP_O 9112"
check  "another network cannot reach the port" check_closed b1 "$IP_O"
S1_ETH=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' varco-s1)
check  "the machine's real address has no SSH" check_closed a1 "$S1_ETH"
stop_server; sleep 2; start_server
RECOVERED=""
for _ in $(seq 60); do
  [ "$(sshz 'echo back' 2>/dev/null)" = "back" ] && { RECOVERED=yes; break; }
  sleep 1
done
[ -n "$RECOVERED" ] && ok "ssh works again after the server restarts" || bad "ssh did not come back"
docker exec -d varco-a1 bash -c "ssh -i /tmp/id $SSH_OPTS root@$IP_O 'sleep 986'"
sleep 2
check  "a remote process is running" ex s1 "pgrep -f '[s]leep 986'"
ex s1 "pkill -INT -x varco"
sleep 3
refuse "leaving ends remote processes" ex s1 "pgrep -f '[s]leep 986'"

echo "== one-click start: settings file and command line"
# Odd name on purpose: the settings file follows the executable's own name.
ex s1 "mkdir -p /tmp/app; cp $BIN /tmp/app/tool-1.2.3-x; rm -f /tmp/app/*.toml"
TOOL=/tmp/app/tool-1.2.3-x
CONF=/tmp/app/tool-1.2.3-x.toml
OUT_C=$(ex s1 "$TOOL --help" 2>&1); echo "$OUT_C" | grep -q -- '--ssh-pubkey' && ok "--help lists the new options" || bad "--help is missing options"
write_conf() { docker exec -i varco-s1 bash -c "cat > $CONF"; }
ssh_ip_in() { ex s1 "sed -n 's/^SSH 已开启：\\([0-9.]*\\):.*/\\1/p' $1 | tail -1" 2>/dev/null; }
stop_tool() { ex s1 "pkill -INT -x tool-1.2.3-x; true"; sleep 2; }
start_tool() { ex s1 "rm -f /tmp/tool.log"; docker exec -d varco-s1 bash -c "cd / && $TOOL $1 </dev/null >/tmp/tool.log 2>&1"; }
wait_tool_ip() { for _ in $(seq 40); do local ip; ip=$(ssh_ip_in /tmp/tool.log); [ -n "$ip" ] && { echo "$ip"; return 0; }; sleep 0.5; done; return 1; }
sshc() { ex a1 "ssh -i /tmp/id $SSH_OPTS root@$1 $(printf '%q' "$2")"; }
write_conf <<CONF_END
code = "$CODE_A"
ssh_pubkey = "$PUBKEY"
CONF_END
start_tool ""
IP_T=$(wait_tool_ip)
if [ -n "$IP_T" ]; then ok "settings file alone joins and starts SSH"; else bad "settings file did not start"; ex s1 "cat /tmp/tool.log"; fi
[ -z "$(mesh_ip s1)" ] && ok "a key in the file defaults to SSH-only" || bad "a NIC appeared by default"
[ "$(sshc "$IP_T" 'echo from-file')" = "from-file" ] && ok "ssh works with the file's key" || bad "ssh failed with the file's key"
stop_tool

write_conf <<CONF_END
code = "$CODE_A"
ssh_pubkey = "$PUBKEY"
port = 1
CONF_END
start_tool ""
sleep 4
refuse "a wrong port in the file does not connect" test -n "$(ssh_ip_in /tmp/tool.log)"
check  "and says it cannot reach the server" ex s1 "grep -q '失败' /tmp/tool.log"
stop_tool
start_tool "--port $PORT"
IP_T=$(wait_tool_ip)
[ "$(sshc "$IP_T" 'echo from-flag' 2>/dev/null)" = "from-flag" ] && ok "--port beats the file" || { bad "--port did not override"; ex s1 "cat /tmp/tool.log"; }
stop_tool

ex s1 "rm -f $CONF"
start_tool "--code $CODE_A --ssh-pubkey '$PUBKEY'"
IP_T=$(wait_tool_ip)
[ "$(sshc "$IP_T" 'echo no-file' 2>/dev/null)" = "no-file" ] && ok "command line alone is enough" || { bad "command line alone failed"; ex s1 "cat /tmp/tool.log"; }
stop_tool

# Another server is the same as a network redirecting the address: the pin must hold.
docker exec varco-srv cat /etc/varco/config.toml | sed "s/0.0.0.0:$PORT/0.0.0.0:9443/; s/varco-srv:$PORT/varco-a2:9443/" | docker exec -i varco-a2 bash -c "mkdir -p /tmp/other; cat > /tmp/other/config.toml"
docker exec -d varco-a2 bash -c "cd /tmp/other && $BIN server -c /tmp/other/config.toml >/tmp/other/server.log 2>&1"
sleep 2
ex s1 "timeout 15 $TOOL --code $CODE_A --ssh-pubkey '$PUBKEY' --server varco-a2 --port 9443 </dev/null >/tmp/pin.log 2>&1"
check  "--server cannot bypass the certificate pin" ex s1 "grep -q '证书' /tmp/pin.log"
refuse "and nothing joined that server" ex a2 "grep -q 'member online' /tmp/other/server.log"
ex a2 "pkill -f 'server -c /tmp/other/config.toml'; true"

write_conf <<CONF_END
cod = "$CODE_A"
CONF_END
ex s1 "$TOOL </dev/null >/tmp/bad.log 2>&1"
[ $? != 0 ] && ok "a mistyped setting stops the start" || bad "a mistyped setting was ignored"
check  "and names the file" ex s1 "grep -q 'tool-1.2.3-x.toml' /tmp/bad.log"
refuse "and does not print the code" ex s1 "grep -qF '$CODE_A' /tmp/bad.log"
ex s1 "rm -f $CONF"

echo "== secrets stay out of logs"
SECRET_VALUE=$(secret "$OUT_A")
refuse "secret absent from server log" ex srv "grep -qF '$SECRET_VALUE' /tmp/server.log"
refuse "secret absent from client log" ex a1  "grep -qF '$SECRET_VALUE' /tmp/client.log"

echo
echo "server log excerpt:"; ex srv "tail -5 /tmp/server.log"
echo "passed $PASS, failed $FAIL"
[ "$FAIL" = 0 ]
