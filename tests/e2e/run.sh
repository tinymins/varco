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
BIN=/target/debug/varco
DATA=/var/lib/varco
start_server() { docker exec -d varco-srv bash -c "$BIN server --data-dir $DATA >>/tmp/server.log 2>&1"; }
stop_server()  { ex srv "pkill -x varco"; }
join() { docker exec -d -e "VARCO_CREDENTIAL=$2" "varco-$1" bash -c "$BIN >>/tmp/client.log 2>&1"; }
mesh_ip() { ex "$1" "ip -4 -o addr | awk '\$2!=\"lo\" && \$2!=\"eth0\" {print \$4}' | cut -d/ -f1 | head -1"; }
wait_ip() { for _ in $(seq 60); do local ip; ip=$(mesh_ip "$1"); [ -n "$ip" ] && { echo "$ip"; return 0; }; sleep 0.5; done; return 1; }
ping1() { ex "$1" "ping -c1 -W2 $2"; }
wait_ping() { for _ in $(seq "${3:-60}"); do ping1 "$1" "$2" >/dev/null 2>&1 && return 0; sleep 1; done; return 1; }

# The console, as a person would drive it. ADMIN can point at another instance.
ADMIN=8444; COOKIES=/tmp/console.cookies
api() {
  local method=$1 path=$2 body=${3:-'{}'}
  if [ "$method" = GET ]; then
    docker exec varco-srv curl -s -b "$COOKIES" "http://127.0.0.1:$ADMIN/api/$path"
  else
    docker exec varco-srv curl -s -b "$COOKIES" -c "$COOKIES" -X "$method" \
      -H 'Content-Type: application/json' -d "$body" "http://127.0.0.1:$ADMIN/api/$path"
  fi
}
status() {
  local method=$1 path=$2 body=${3:-'{}'}
  docker exec varco-srv curl -s -o /dev/null -w '%{http_code}' -b "$COOKIES" -c "$COOKIES" -X "$method" \
    -H 'Content-Type: application/json' -d "$body" "http://127.0.0.1:$ADMIN/api/$path"
}
field() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
number() { sed -n "s/.*\"$1\":\([0-9]*\).*/\1/p"; }
new_code() { local body=${2:-}; [ -n "$body" ] || body='{}'; api POST "w/$1/codes" "$body" | field code; }
wait_console() { for _ in $(seq 40); do docker exec varco-srv curl -sf -o /dev/null "http://127.0.0.1:$ADMIN/healthz" && return 0; sleep 0.25; done; return 1; }

echo "== first run"
start_server
wait_console || { ex srv 'cat /tmp/server.log'; exit 1; }
[ "$(status POST login '{"username":"root","password":"wrong"}')" = 401 ] && ok "a wrong password is refused" || bad "a wrong password was accepted"
[ "$(status POST login '{"username":"root","password":"admin"}')" = 204 ] && ok "the default account logs in" || bad "the default account did not log in"
[ "$(docker exec varco-srv curl -s -o /dev/null -w '%{http_code}' -b "$COOKIES" "http://127.0.0.1:$ADMIN/api/workspaces")" = 403 ] && ok "nothing opens before the password is changed" || bad "the console opened with the default password"
refuse "the relay does not listen before it is set up" ex srv "nc -z -w1 127.0.0.1 $PORT"
[ "$(status POST me/password '{"password":"admin"}')" = 204 ] && ok "the new password may equal the old one" || bad "the same password was refused"
SETTINGS="{\"public_addr\":\"varco-srv:$PORT\",\"relay_listen\":\"0.0.0.0:$PORT\"}"
[ "$(status PUT settings "$SETTINGS")" = 204 ] && ok "the relay can be set up" || bad "relay setup failed"
sleep 0.5
check  "the relay now listens" ex srv "nc -z -w1 127.0.0.1 $PORT"
WS_A=$(api POST workspaces '{"name":"a","cidr":"10.77.1.0/24"}' | number id)
WS_B=$(api POST workspaces '{"name":"b","cidr":"10.77.2.0/24"}' | number id)
[ -n "$WS_A" ] && [ -n "$WS_B" ] || { echo "no workspaces created"; ex srv 'cat /tmp/server.log'; exit 1; }
CODE_A=$(new_code "$WS_A"); CODE_B=$(new_code "$WS_B")
[ -n "$CODE_A" ] && [ -n "$CODE_B" ] || { echo "no Codes created"; exit 1; }

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
REVOKED_REPLY=$(api POST "w/$WS_A/codes" '{"note":"to revoke"}')
UNLISTED=$(echo "$REVOKED_REPLY" | field code)
api POST "w/$WS_A/codes/$(echo "$REVOKED_REPLY" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')/revoke" >/dev/null
expect_msg "revoked Code is rejected"      "$UNLISTED" "无效或已被撤销"
expect_msg "malformed code is rejected"    "garbage"   "格式不正确"
# A different server key gives a valid code whose pin does not match this server.
docker exec -d varco-srv bash -c "$BIN server --data-dir /tmp/other --admin-listen 127.0.0.1:8445 >>/tmp/other.log 2>&1"
ADMIN=8445; COOKIES=/tmp/other.cookies
wait_console
status POST login '{"username":"root","password":"admin"}' >/dev/null
status POST me/password '{"password":"x"}' >/dev/null
status PUT settings "{\"public_addr\":\"varco-srv:$PORT\"}" >/dev/null
OTHER_WS=$(api POST workspaces '{"name":"other","cidr":"10.88.0.0/24"}' | number id)
WRONG_PIN=$(new_code "$OTHER_WS")
ex srv "pkill -f 'data-dir /tmp/other'; true"
ADMIN=8444; COOKIES=/tmp/console.cookies
expect_msg "wrong pin (simulated MITM) is rejected" "$WRONG_PIN" "证书与 Code 不符"
REFUSED=$(ex srv "grep -c 'connection rejected' /tmp/server.log")
[ "$REFUSED" = 1 ] && ok "only the revoked secret reached the server's auth step" \
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
docker exec -d varco-a2 bash -c "mkdir -p /tmp/other; $BIN server --data-dir /tmp/other/data --admin-listen 127.0.0.1:8445 >/tmp/other/server.log 2>&1"
sleep 2
ex a2 "J='Content-Type: application/json'; U=http://127.0.0.1:8445/api; C=/tmp/other/cookies
  curl -s -c \$C -H \"\$J\" -d '{\"username\":\"root\",\"password\":\"admin\"}' \$U/login
  curl -s -b \$C -H \"\$J\" -d '{\"password\":\"x\"}' \$U/me/password
  curl -s -b \$C -H \"\$J\" -X PUT -d '{\"public_addr\":\"varco-a2:9443\",\"relay_listen\":\"0.0.0.0:9443\"}' \$U/settings"
sleep 1
ex s1 "timeout 15 $TOOL --code $CODE_A --ssh-pubkey '$PUBKEY' --server varco-a2 --port 9443 </dev/null >/tmp/pin.log 2>&1"
check  "--server cannot bypass the certificate pin" ex s1 "grep -q '证书' /tmp/pin.log"
refuse "and nothing joined that server" ex a2 "grep -q 'member online' /tmp/other/server.log"
ex a2 "pkill -f 'data-dir /tmp/other/data'; true"

write_conf <<CONF_END
cod = "$CODE_A"
CONF_END
ex s1 "$TOOL </dev/null >/tmp/bad.log 2>&1"
[ $? != 0 ] && ok "a mistyped setting stops the start" || bad "a mistyped setting was ignored"
check  "and names the file" ex s1 "grep -q 'tool-1.2.3-x.toml' /tmp/bad.log"
refuse "and does not print the code" ex s1 "grep -qF '$CODE_A' /tmp/bad.log"
ex s1 "rm -f $CONF"

echo "== one Code carries the SSH key"
ex s1 "pkill -x varco; pkill -x tool-1.2.3-x; true"; sleep 1
JOINT=$(ex a1 "$BIN code add-ssh-key --code $CODE_A --ssh-pubkey /tmp/id.pub" | grep '^varco://')
[ -n "$JOINT" ] && ok "add-ssh-key reads a key file and prints a Code" || bad "add-ssh-key printed no Code"
start_code() { ex s1 "rm -f /tmp/joint.log"; docker exec -d -e "VARCO_CREDENTIAL=$1" varco-s1 bash -c "$BIN </dev/null >/tmp/joint.log 2>&1"; }
wait_code_ip() { for _ in $(seq 40); do local ip; ip=$(ssh_ip_in /tmp/joint.log); [ -n "$ip" ] && { echo "$ip"; return 0; }; sleep 0.5; done; return 1; }
stop_code() { ex s1 "pkill -INT -x varco; true"; sleep 2; }
start_code "$JOINT"
IP_J=$(wait_code_ip)
if [ -n "$IP_J" ]; then ok "the Code alone joins and starts SSH, with no server restart"; else bad "the Code did not start SSH"; ex s1 "cat /tmp/joint.log"; fi
[ -z "$(mesh_ip s1)" ] && ok "a key in the Code defaults to SSH-only" || bad "a NIC appeared"
check  "and says who gets control" ex s1 "grep -q '远程控制' /tmp/joint.log"
[ "$(sshc "$IP_J" 'echo from-code')" = "from-code" ] && ok "ssh works with the key in the Code" || bad "ssh failed with the key in the Code"
refuse "ssh with another key is refused" ex a1 "ssh -i /tmp/other -o IdentitiesOnly=yes $SSH_OPTS root@$IP_J true"
stop_code
check  "the Code without the key still works" wait_ping a1 "$IP_A2" 30

CODE_K=$(api POST "w/$WS_A/codes" "{\"ssh_pubkey\":\"$PUBKEY\"}" | field code)
start_code "$CODE_K"
IP_J=$(wait_code_ip)
[ "$(sshc "$IP_J" 'echo from-gen' 2>/dev/null)" = "from-gen" ] && ok "the console makes a working Code with a key" || { bad "the console's Code with a key failed"; ex s1 "cat /tmp/joint.log"; }
stop_code

ex a1 "$BIN code add-ssh-key --code $CODE_A --ssh-pubkey /tmp/id >/tmp/priv.log 2>&1"
[ $? != 0 ] && ok "a private key is refused" || bad "a private key was accepted"
refuse "and is not printed" ex a1 "grep -q 'PRIVATE\|^b3Blbn' /tmp/priv.log"
ex a1 "VARCO_CREDENTIAL=varco1.AAAA $BIN >/tmp/old.log 2>&1"
check  "the old Code format is refused" ex a1 "grep -q '格式不正确' /tmp/old.log"

echo "== console: Codes, kicks and bans"
member_field() { api GET "w/$WS_A/members" | sed 's/},{/}\n{/g' | grep "\"hostname\":\"$1\"" | field "$2"; }
stop_a3() { ex a3 "pkill -x varco; true"; for _ in $(seq 30); do [ -z "$(mesh_ip a3)" ] && return 0; sleep 0.5; done; return 1; }
a3_exits_with() { for _ in $(seq 60); do
    ex a3 "pgrep -x varco" >/dev/null || { ex a3 "tail -3 /tmp/client.log" | grep -q "$1"; return; }
    sleep 0.5; done; return 1; }
join_a3() { join a3 "$1"; IP_A3=$(wait_ip a3); [ -n "$IP_A3" ] && wait_ping a1 "$IP_A3" 20; }
item_id() { sed -n 's/.*"id":"\([^"]*\)".*/\1/p'; }

check  "the page is served" ex srv "curl -s http://127.0.0.1:8444/ | grep -q 'varco 管理后台'"
stop_a3
# The image has no machine id of its own; this stands in for a real machine's.
ex a3 "echo 0123456789abcdef0123456789abcdef > /etc/machine-id"
ONCE=$(new_code "$WS_A" '{"max_uses":1,"note":"e2e"}')
join_a3 "$ONCE" && ok "a once Code joins with no server restart" || bad "the once Code did not join"
sleep 1
expect_msg "a second run is refused the once Code" "$ONCE" "已被使用"
stop_server; sleep 2; start_server; wait_console
check  "its client comes back after a server restart" wait_ping a1 "$IP_A3" 40
[ "$(status GET me)" != 401 ] && ok "the login survives a server restart" || bad "logged out by a restart"
expect_msg "and it is still refused to others" "$ONCE" "已被使用"

api POST "w/$WS_A/members/kick" "{\"id\":\"$(member_field a3 id)\"}" >/dev/null
a3_exits_with "已被管理员移出" && ok "a kicked client stops instead of reconnecting" || bad "the kicked client did not stop"
expect_msg "a kick does not refund the once Code" "$ONCE" "已被使用"

TIMED_REPLY=$(api POST "w/$WS_A/codes" '{"duration":"1h"}')
TIMED=$(echo "$TIMED_REPLY" | field code); TIMED_ID=$(echo "$TIMED_REPLY" | item_id)
stop_a3
join_a3 "$TIMED" && ok "a timed Code joins" || bad "the timed Code did not join"
DEVICE=$(member_field a3 device)
[ -n "$DEVICE" ] && ok "the device id is reported from the machine id" || bad "no device id reported"
BAN_ID=$(api POST "w/$WS_A/bans" "{\"kind\":\"device\",\"value\":\"$DEVICE\"}" | item_id)
a3_exits_with "已被管理员移出" && ok "banning the device removes it" || bad "the banned device stayed"
join a3 "$CODE_A"
a3_exits_with "已被管理员移出" && ok "the banned device stays out with another Code" || bad "the banned device got back in"
stop_a3
docker exec -d -e "VARCO_CREDENTIAL=$CODE_B" varco-a3 bash -c "$BIN >>/tmp/client.log 2>&1"
if [ -n "$(wait_ip a3)" ]; then ok "the same device is welcome in another workspace"; else bad "a workspace's ban reached another"; fi
stop_a3
api DELETE "w/$WS_A/bans/$BAN_ID" >/dev/null
join_a3 "$TIMED" && ok "lifting the ban lets it back" || bad "still out after the ban was lifted"

A3_ETH=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' varco-a3)
BAN_ID=$(api POST bans "{\"kind\":\"ip\",\"value\":\"$A3_ETH\"}" | item_id)
refuse "a global address ban cuts it off" bash -c "sleep 2; docker exec varco-a1 ping -c1 -W2 $IP_A3"
check  "and the client keeps trying without being told why" ex a3 "pgrep -x varco"
api DELETE "bans/$BAN_ID" >/dev/null
check  "lifting the address ban restores it" wait_ping a1 "$IP_A3" 40

api POST "w/$WS_A/codes/$TIMED_ID/revoke" >/dev/null
a3_exits_with "无效或已被撤销" && ok "revoking a Code removes who came with it" || bad "the revoked Code's client stayed"

echo "== console: workspaces and accounts"
WS_C=$(api POST workspaces '{"name":"team-c","cidr":"10.77.1.0/24","owner_username":"carol","owner_password":"first"}' | number id)
[ -n "$WS_C" ] && ok "a workspace can be created with its owner while running" || bad "the workspace was not created"
ADMIN=8444; ROOT_COOKIES=$COOKIES; COOKIES=/tmp/carol.cookies
[ "$(status POST login '{"username":"carol","password":"first"}')" = 204 ] && ok "its owner logs in" || bad "its owner did not log in"
status POST me/password '{"password":"chosen"}' >/dev/null
[ "$(status GET "w/$WS_C/members")" = 200 ] && ok "an owner reaches their workspace" || bad "an owner was refused their workspace"
[ "$(status GET "w/$WS_A/members")" = 404 ] && ok "and no other, which appears not to exist" || bad "an owner reached another workspace"
[ "$(status GET workspaces)" = 403 ] && ok "and nothing of the super administrator's" || bad "an owner reached the workspace list"
CODE_C=$(new_code "$WS_C")
stop_a3
join a3 "$CODE_C"
IP_C=$(wait_ip a3)
[ -n "$IP_C" ] && ok "their Code joins their network" || bad "their Code did not join"
TOKEN=$(api POST "w/$WS_C/tokens" '{"name":"e2e"}' | field token)
COOKIES=$ROOT_COOKIES
# Its addresses are also in use in workspace a. The one member here has only itself
# to reach, so anything answering would have come from the other workspace.
[ "$IP_C" != "$IP_A2" ] || bad "expected different addresses for this check"
refuse "a same-range workspace is unreachable" ping1 a3 "$IP_A2"
if ex a3 "ip -4 -o addr | grep -q ' $IP_C/'"; then ok "the same address exists in both"; else bad "a3 does not hold its address"; fi
bearer() { docker exec varco-srv curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "http://127.0.0.1:$ADMIN$2"; }
[ "$(bearer "$TOKEN" "/api/w/$WS_C/members")" = 200 ] && ok "a workspace token works there" || bad "the workspace token was refused"
[ "$(bearer "$TOKEN" "/api/w/$WS_A/members")" = 404 ] && ok "and nowhere else" || bad "the workspace token reached another workspace"
[ "$(bearer "$TOKEN" /metrics)" = 403 ] && ok "and not on metrics" || bad "the workspace token read metrics"
ROOT_TOKEN=$(api POST tokens '{"name":"e2e-root"}' | field token)
check  "a super token reads metrics" ex srv "curl -s -H 'Authorization: Bearer $ROOT_TOKEN' http://127.0.0.1:$ADMIN/metrics | grep -q 'varco_members_online{workspace=\"team-c\"} 1'"
check  "health needs no login" ex srv "curl -s http://127.0.0.1:$ADMIN/healthz | grep -q 'relay_listening\":true'"
api DELETE "workspaces/$WS_C" >/dev/null
a3_exits_with "无效或已被撤销" && ok "deleting a workspace stops its clients" || bad "the deleted workspace's client stayed"
check  "and leaves the others alone" wait_ping a1 "$IP_A2" 10
[ "$(api GET "w/$WS_A/connections" | number total)" -gt 0 ] && ok "connections are in the history" || bad "no connection history"

check  "the database is private" bash -c "[ \"\$(docker exec varco-srv stat -c %a $DATA/varco.db)\" = 600 ]"
refuse "no Code in the database"       ex srv "grep -aqF '$ONCE' $DATA/varco.db"
refuse "no password in the database"   ex srv "grep -aqF 'chosen' $DATA/varco.db"
refuse "no Code in the server log"     ex srv "grep -qF '$ONCE' /tmp/server.log"
refuse "no password in the server log" ex srv "grep -qF 'chosen' /tmp/server.log"
docker exec varco-srv $BIN server --data-dir $DATA reset-root-password >/dev/null
[ "$(status GET me)" = 401 ] && ok "resetting the root password ends its logins" || bad "root stayed logged in after a reset"
[ "$(status POST login '{"username":"root","password":"admin"}')" = 204 ] && ok "and restores the default" || bad "the default did not come back"

echo "== secrets stay out of logs"
refuse "Code absent from server log" ex srv "grep -qF '$CODE_A' /tmp/server.log"
refuse "Code absent from client log" ex a1  "grep -qF '$CODE_A' /tmp/client.log"

echo
echo "server log excerpt:"; ex srv "tail -5 /tmp/server.log"
echo "passed $PASS, failed $FAIL"
[ "$FAIL" = 0 ]
