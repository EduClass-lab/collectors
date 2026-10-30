import json
import urllib.parse
import sys
import base64
import re

INPUT_FILE = "proxies.txt"
CONFIG_OUTPUT_FILE = "singbox_config.json"
MAP_OUTPUT_FILE = "tag_map.json"

def to_string(value, default=""):
    if value is None:
        return default
    return str(value)

def decode_base64(value):
    value = value.strip()
    value += "=" * (-len(value) % 4)

    try:
        return base64.urlsafe_b64decode(value).decode("utf-8")
    except Exception:
        return base64.b64decode(value).decode("utf-8")

def parse_vless(link, index):
    parsed_url = urllib.parse.urlparse(link)

    hostname = parsed_url.hostname
    port = parsed_url.port
    uuid = parsed_url.username

    if not hostname or not port or not uuid:
        raise ValueError("Invalid VLESS server, port, or UUID")

    params = urllib.parse.parse_qs(parsed_url.query)

    original_tag = (
        urllib.parse.unquote(parsed_url.fragment)
        if parsed_url.fragment
        else f"proxy-{index}"
    )

    safe_tag = f"proxy-{index}"

    config = {
        "type": "vless",
        "tag": safe_tag,
        "server": str(hostname),
        "server_port": int(port),
        "uuid": str(urllib.parse.unquote(uuid))
    }

    security = params.get("security", [""])[0]

    if security == "tls":
        config["tls"] = {
            "enabled": True,
            "insecure": True,
            "server_name": str(
                params.get("sni", [hostname])[0]
            )
        }

    transport_type = params.get("type", [""])[0]

    if transport_type == "ws":
        config["transport"] = {
            "type": "ws",
            "path": params.get("path", ["/"])[0],
            "headers": {
                "Host": str(
                    params.get("host", [hostname])[0]
                )
            }
        }

    return config, safe_tag, original_tag

def parse_vmess(link, index):
    encoded_part = link[len("vmess://"):]

    decoded_json = json.loads(
        decode_base64(encoded_part)
    )

    hostname = decoded_json.get("add")
    port = decoded_json.get("port")
    uuid = decoded_json.get("id")

    if hostname is None or port is None or uuid is None:
        raise ValueError("Missing VMess server information")

    original_tag = to_string(
        decoded_json.get("ps"),
        f"proxy-{index}"
    )

    safe_tag = f"proxy-{index}"

    config = {
        "type": "vmess",
        "tag": safe_tag,

        # IMPORTANT:
        # Always make server a string.
        "server": str(hostname),

        "server_port": int(port),
        "uuid": str(uuid),

        "security": str(
            decoded_json.get("scy", "auto")
        ),

        "alter_id": int(
            decoded_json.get("aid", 0)
        )
    }

    if decoded_json.get("tls", "") == "tls":
        config["tls"] = {
            "enabled": True,
            "insecure": True,
            "server_name": str(
                decoded_json.get("sni", hostname)
            )
        }

    if decoded_json.get("net", "") == "ws":
        config["transport"] = {
            "type": "ws",
            "path": str(
                decoded_json.get("path", "/")
            ),
            "headers": {
                "Host": str(
                    decoded_json.get("host", hostname)
                )
            }
        }

    return config, safe_tag, original_tag

def parse_ss(link, index):
    parsed_url = urllib.parse.urlparse(link)

    original_tag = (
        urllib.parse.unquote(parsed_url.fragment)
        if parsed_url.fragment
        else f"proxy-{index}"
    )

    safe_tag = f"proxy-{index}"

    if parsed_url.username and parsed_url.hostname:
        user_info = urllib.parse.unquote(
            parsed_url.username
        )

        password = urllib.parse.unquote(
            parsed_url.password or ""
        )

        method = user_info
        server = parsed_url.hostname
        port = parsed_url.port

    else:
        encoded_part = parsed_url.netloc.split("@")[0]

        decoded_part = decode_base64(encoded_part)

        user_info, server_info = decoded_part.rsplit(
            "@", 1
        )

        method, password = user_info.split(":", 1)

        server_url = urllib.parse.urlparse(
            "//" + server_info
        )

        server = server_url.hostname
        port = server_url.port

    if not server or not port or not method:
        raise ValueError(
            "Invalid Shadowsocks configuration"
        )

    config = {
        "type": "shadowsocks",
        "tag": safe_tag,
        "server": str(server),
        "server_port": int(port),
        "method": str(method),
        "password": str(password)
    }

    return config, safe_tag, original_tag

def parse_trojan(link, index):
    parsed_url = urllib.parse.urlparse(link)

    params = urllib.parse.parse_qs(
        parsed_url.query
    )

    hostname = parsed_url.hostname
    port = parsed_url.port
    password = parsed_url.username

    if not hostname or not port or not password:
        raise ValueError(
            "Invalid Trojan server information"
        )

    original_tag = (
        urllib.parse.unquote(parsed_url.fragment)
        if parsed_url.fragment
        else f"proxy-{index}"
    )

    safe_tag = f"proxy-{index}"

    config = {
        "type": "trojan",
        "tag": safe_tag,
        "server": str(hostname),
        "server_port": int(port),
        "password": str(
            urllib.parse.unquote(password)
        ),

        "tls": {
            "enabled": True,
            "insecure": True,
            "server_name": str(
                params.get("sni", [hostname])[0]
            )
        }
    }

    return config, safe_tag, original_tag

parsers = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "ss://": parse_ss,
    "trojan://": parse_trojan
}

outbounds = []
tag_map = {}

skipped_count = 0
processed_count = 0

try:
    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:
        links = [
            line.strip()
            for line in file
            if line.strip()
        ]

    print(
        f"Read {len(links)} total links. Processing..."
    )

    for index, link in enumerate(links, start=1):

        parser = None

        # Normalize protocol prefixes.
        link = link.strip()

        if link.startswith("hy2://"):
            link = "hysteria2://" + link[6:]

        for prefix, parser_func in parsers.items():
            if link.startswith(prefix):
                parser = parser_func
                break

        if parser is None:
            skipped_count += 1
            continue

        try:
            proxy_config, safe_tag, original_tag = (
                parser(link, index)
            )

            if not proxy_config:
                skipped_count += 1
                continue

            # Critical validation:
            # Sing-box expects server to be a string.
            if "server" in proxy_config:
                proxy_config["server"] = str(
                    proxy_config["server"]
                )

            if not isinstance(
                proxy_config.get("server_port"),
                int
            ):
                proxy_config["server_port"] = int(
                    proxy_config["server_port"]
                )

            if not proxy_config.get("server"):
                raise ValueError(
                    "Empty server address"
                )

            if not proxy_config.get("server_port"):
                raise ValueError(
                    "Invalid server port"
                )

            outbounds.append(proxy_config)

            tag_map[safe_tag] = original_tag

            processed_count += 1

        except Exception as error:
            skipped_count += 1

            print(
                f"Skipping proxy #{index}: {error}"
            )

except FileNotFoundError:
    print(
        f"ERROR: Input file '{INPUT_FILE}' not found.",
        file=sys.stderr
    )

    sys.exit(1)

# Remove duplicate outbounds.
unique_outbounds = []
seen = set()

for outbound in outbounds:
    key = json.dumps(
        outbound,
        sort_keys=True,
        ensure_ascii=False
    )

    if key not in seen:
        seen.add(key)
        unique_outbounds.append(outbound)

outbounds = unique_outbounds

final_config = {
    "log": {
        "level": "warn"
    },

    "inbounds": [
        {
            "type": "tun",
            "tag": "tun-in"
        }
    ],

    "outbounds": outbounds
}

# Validate generated JSON before saving.
try:
    json.dumps(
        final_config,
        ensure_ascii=False
    )

except Exception as error:
    print(
        f"ERROR: Generated configuration is invalid: {error}",
        file=sys.stderr
    )

    sys.exit(1)

with open(
    CONFIG_OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:
    json.dump(
        final_config,
        file,
        indent=2,
        ensure_ascii=False
    )

with open(
    MAP_OUTPUT_FILE,
    "w",
    encoding="utf-8"
) as file:
    json.dump(
        tag_map,
        file,
        indent=2,
        ensure_ascii=False
    )

print(
    f"Successfully processed {processed_count} nodes."
)

print(
    f"Unique outbounds: {len(outbounds)}"
)

print(
    f"Skipped {skipped_count} unsupported or invalid links."
)

print(
    f"Created '{CONFIG_OUTPUT_FILE}' and '{MAP_OUTPUT_FILE}'."
)

if not outbounds:
    print(
        "ERROR: No valid proxies were generated.",
        file=sys.stderr
    )

    sys.exit(1)

