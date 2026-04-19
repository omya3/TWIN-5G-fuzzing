# Remote Ubuntu 22.04 Setup Plan

This guide maps the current prototype to the remote machine:

- Host: Ubuntu 22.04.5 LTS
- Available already: `python3`, `git`, `docker`, `tcpdump`, `tshark`
- Missing in the current environment check: `Open5GS`, `UERANSIM`

## Goal of This Phase

Bring up a minimal `Open5GS + UERANSIM` software-only 5G setup on the remote
machine, then capture one valid `NGAP/NAS` registration trace for mutation work.

## Step 1: Install Open5GS and MongoDB

Use the official Open5GS Ubuntu/Debian quickstart flow for Ubuntu 22.04.

### MongoDB

```bash
sudo apt update
sudo apt install -y gnupg curl
curl -fsSL https://pgp.mongodb.com/server-8.0.asc | \
  sudo gpg -o /usr/share/keyrings/mongodb-server-8.0.gpg --dearmor

echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-8.0.gpg ] \
https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/8.0 multiverse" | \
  sudo tee /etc/apt/sources.list.d/mongodb-org-8.0.list

sudo apt update
sudo apt install -y mongodb-org
sudo systemctl enable --now mongod
```

### Open5GS

```bash
sudo add-apt-repository -y ppa:open5gs/latest
sudo apt update
sudo apt install -y open5gs
```

## Step 2: Verify Open5GS Components

```bash
which open5gs-amfd
systemctl status open5gs-amfd --no-pager | head -20
systemctl status mongod --no-pager | head -20
```

If the AMF is inactive, start it:

```bash
sudo systemctl enable --now open5gs-amfd
```

## Step 3: Install UERANSIM

The simplest path is to build from source:

```bash
sudo apt update
sudo apt install -y make gcc g++ libsctp-dev lksctp-tools iproute2 \
  libssl-dev libyaml-cpp-dev pkg-config cmake

cd ~
git clone https://github.com/aligungr/UERANSIM
cd UERANSIM
make
```

Verify:

```bash
ls -l ~/UERANSIM/build/nr-gnb ~/UERANSIM/build/nr-ue
```

## Step 3.5: Add Subscriber Without WebUI

If the Open5GS WebUI cannot be installed because of temporary network or DNS
issues, use the packaged CLI helper instead. The Open5GS quickstart notes that
the WebUI is convenient but not essential because a command line tool is also
available.

First, locate the helper script:

```bash
dpkg -L open5gs | grep 'open5gs-dbctl$'
```

Then print its usage:

```bash
sudo "$(dpkg -L open5gs | grep 'open5gs-dbctl$' | head -1)"
```

For the current UERANSIM test UE, add a subscriber using IMSI, key, OPC, and
the default `internet` APN:

```bash
DBCTL="$(dpkg -L open5gs | grep 'open5gs-dbctl$' | head -1)"
sudo "$DBCTL" add_ue_with_apn \
  001010000000001 \
  465B5CE8B199B49FAA5F0A2EE238A6BC \
  E8ED289DEBA952E4283B54E88E6183CA \
  internet
```

If `add_ue_with_apn` is not supported in the installed script version, use:

```bash
sudo "$DBCTL" add \
  001010000000001 \
  465B5CE8B199B49FAA5F0A2EE238A6BC \
  E8ED289DEBA952E4283B54E88E6183CA
```

## Step 4: Minimal Integration Check

Before full fuzzing, confirm that a clean registration is possible.

Tasks:

1. configure Open5GS subscriber data,
2. align `MCC/MNC`, `AMF IP`, and `gNB config`,
3. bring up `nr-gnb`,
4. bring up `nr-ue`,
5. confirm AMF-side registration logs.

## Step 5: Capture NGAP Trace

Once a successful registration works, capture NGAP on SCTP port `38412`.

Example:

```bash
mkdir -p ~/twin-traces
sudo tshark -i any -f "sctp port 38412" -w ~/twin-traces/ngap-registration.pcapng
```

In another terminal, run the clean registration flow. Stop capture after the UE
registers successfully.

## Step 6: Export Decode-Friendly Output

Export a readable summary:

```bash
tshark -r ~/twin-traces/ngap-registration.pcapng -Y "ngap" -V \
  > ~/twin-traces/ngap-registration.txt
```

Optional JSON export:

```bash
tshark -r ~/twin-traces/ngap-registration.pcapng -Y "ngap" -T json \
  > ~/twin-traces/ngap-registration.json
```

## What We Need Next

After the first successful run, the next artifacts to bring back are:

- one `pcapng` capture,
- one text or JSON decode from `tshark`,
- the exact `Open5GS` and `UERANSIM` config files used.

These will let us:

1. build a real structured trace from captured traffic,
2. attach the current mutation engine to actual messages,
3. start comparing baseline and NAS-aware mutations.

## References

- Open5GS Quickstart:
  https://open5gs.org/open5gs/docs/guide/01-quickstart/
- Open5GS Build Guide:
  https://open5gs.org/open5gs/docs/guide/02-building-open5gs-from-sources/
- UERANSIM Installation Wiki:
  https://github.com/aligungr/UERANSIM/wiki/Installation
