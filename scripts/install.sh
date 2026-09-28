#!/bin/sh
set -eu

# Install only on OpenWrt; download-only supports other Linux systems.
release=v0.1.1
base="https://github.com/hamidzr/filter-merge/releases/download/$release"
download_dir=
urls=
while [ "$#" -gt 0 ]; do
  case "$1" in
  --download-only)
    [ "$#" -ge 2 ] || {
      echo 'missing download directory' >&2
      exit 1
    }
    download_dir=$2
    shift 2
    ;;
  --url)
    [ "$#" -ge 2 ] || {
      echo 'missing source URL' >&2
      exit 1
    }
    case "$2" in
    http://* | https://*) ;;
    *)
      echo 'sources must use HTTP or HTTPS' >&2
      exit 1
      ;;
    esac
    case "$2" in
    *'
'* | *"$(printf '\r')"*)
      echo 'invalid source URL' >&2
      exit 1
      ;;
    esac
    urls="${urls}url=$2
"
    shift 2
    ;;
  *)
    echo 'usage: install.sh [--url URL ...] [--download-only DIRECTORY]' >&2
    exit 1
    ;;
  esac
done
[ "$(uname -s)" = Linux ] || {
  echo 'release installer supports Linux only' >&2
  exit 1
}
case "$(uname -m)" in
aarch64 | arm64) arch=aarch64 ;;
x86_64 | amd64) arch=x86_64 ;;
*)
  echo 'supported architectures: aarch64, x86_64' >&2
  exit 1
  ;;
esac
if [ -z "$download_dir" ]; then
  [ -f /etc/openwrt_release ] || {
    echo 'automatic service setup requires OpenWrt; use --download-only DIRECTORY elsewhere' >&2
    exit 1
  }
  [ "$(id -u)" = 0 ] || {
    echo 'OpenWrt installation requires root' >&2
    exit 1
  }
fi
for command in curl tar sha256sum mktemp; do
  command -v "$command" >/dev/null || {
    echo "missing command: $command" >&2
    exit 1
  }
done
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
asset="filter-merge-$release-$arch-linux-musl.tar.gz"
curl -fSL --retry 2 --connect-timeout 15 --max-time 180 "$base/$asset" -o "$stage/$asset"
curl -fSL --retry 2 --connect-timeout 15 --max-time 30 "$base/SHA256SUMS" -o "$stage/SHA256SUMS"
checksum=$(awk -v asset="$asset" '$2 == asset { print $1 }' "$stage/SHA256SUMS")
[ "${#checksum}" = 64 ] || {
  echo 'missing release checksum' >&2
  exit 1
}
(cd "$stage" && printf '%s  %s\n' "$checksum" "$asset" | sha256sum -c -)
tar -xzf "$stage/$asset" -C "$stage"
"$stage/filter-merge" --version
if [ -n "$download_dir" ]; then
  mkdir -p "$download_dir"
  cp "$stage/filter-merge" "$stage/filter-merge.conf" "$stage/filter-merge.init" "$download_dir/"
  echo "Downloaded and verified $release in $download_dir"
  exit 0
fi
# Prepare config before stopping a working service; preserve it on upgrades.
if [ -n "$urls" ]; then
  if [ -f /etc/filter-merge.conf ]; then
    echo 'existing config preserved; edit /etc/filter-merge.conf to change sources' >&2
    exit 1
  fi
  sed '/^url=/d' "$stage/filter-merge.conf" >"$stage/config"
  printf '%s' "$urls" >>"$stage/config"
else
  cp "$stage/filter-merge.conf" "$stage/config"
fi
if [ -x /etc/init.d/filter-merge ]; then
  /etc/init.d/filter-merge stop
fi
cp "$stage/filter-merge" /usr/bin/filter-merge.next
chmod 755 /usr/bin/filter-merge.next
mv /usr/bin/filter-merge.next /usr/bin/filter-merge
cp "$stage/filter-merge.init" /etc/init.d/filter-merge
chmod 755 /etc/init.d/filter-merge
if [ ! -f /etc/filter-merge.conf ]; then
  cp "$stage/config" /etc/filter-merge.conf
fi
for path in /usr/bin/filter-merge /etc/init.d/filter-merge /etc/filter-merge.conf; do
  touch /etc/sysupgrade.conf
  grep -qxF "$path" /etc/sysupgrade.conf || printf '%s\n' "$path" >>/etc/sysupgrade.conf
done
/etc/init.d/filter-merge enable
/etc/init.d/filter-merge start
# procd startup is asynchronous; health does not download source lists.
curl -fsS --retry 5 --retry-connrefused --retry-delay 1 --max-time 5 http://127.0.0.1:3054/healthz
echo '
Installed. Add http://127.0.0.1:3054/filters.txt as an AdGuard DNS blocklist.'
echo 'After successful download, disable original subscriptions included in the merger.'
