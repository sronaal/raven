import asyncio
import socket
import logging

logger = logging.getLogger(__name__)

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1433, 1521, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    3306, 3389, 3690, 4333, 4444, 4700, 4848, 5000, 5060, 5222, 5228,
    5432, 5555, 5631, 5800, 5900, 5984, 6082, 6379, 6443, 6580, 7001,
    7002, 8000, 8001, 8008, 8009, 8080, 8081, 8083, 8086, 8088, 8089,
    8090, 8091, 8092, 8093, 8096, 8100, 8180, 8181, 8200, 8222, 8243,
    8280, 8300, 8400, 8443, 8500, 8800, 8880, 8888, 8899, 8983, 9000,
    9001, 9043, 9060, 9080, 9090, 9091, 9100, 9200, 9300, 9418, 9443,
    9600, 9999, 10000, 10001, 10050, 10051, 11000, 11211, 12000, 12345,
    16010, 16113, 17000, 18000, 18080, 19000, 19080, 20000, 20720, 21000,
    21306, 22000, 22222, 23000, 24800, 25000, 25565, 26000, 27017, 27018,
    27019, 27107, 28000, 28015, 30000, 30718, 31000, 31337, 32000, 32764,
    32768, 32771, 32773, 32774, 32775, 32776, 32777, 32778, 32779, 32780,
    32800, 33060, 33306, 33434, 33567, 33656, 33848, 33890, 34000, 34443,
    34567, 35000, 35353, 35601, 35602, 36789, 36790, 36865, 37000, 37444,
    37601, 37602, 37777, 37800, 37900, 38000, 38080, 38090, 39000, 39222,
    40000, 40910, 41000, 41111, 41666, 41728, 41772, 42222, 42424, 42444,
    43000, 43047, 43333, 44000, 44044, 44333, 44400, 44441, 44442, 44443,
    44444, 44445, 44500, 44501, 45000, 45002, 45003, 45004, 45005, 45006,
    45007, 45008, 45009, 45010, 45011, 45012, 45013, 45014, 45015, 45016,
    45333, 46000, 46336, 46666, 47000, 47001, 47544, 47777, 48000, 48080,
    49000, 49151, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
    49160, 49161, 49162, 49163, 49164, 49165, 49166, 49167, 49168, 49169,
    49170, 49171, 49172, 49173, 49174, 49175, 49176, 49177, 49178, 49179,
    49180, 49181, 49182, 49183, 49184, 49185, 49186, 49187, 49188, 49189,
    49190, 49191, 49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199,
    49200, 50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008,
    50009, 50010, 50070, 50100, 50200, 50300, 50400, 50500, 50600, 50700,
    50800, 50900, 51000, 51100, 51200, 51300, 51400, 51500, 51600, 51700,
    51800, 51900, 52000, 52100, 52200, 52300, 52400, 52500, 52600, 52700,
    52800, 52900, 53000, 53100, 53200, 53300, 53400, 53500, 53600, 53700,
    53800, 53900, 54000, 54100, 54200, 54300, 54400, 54500, 54600, 54700,
    54800, 54900, 55000, 55100, 55200, 55300, 55400, 55500, 55600, 55700,
    55800, 55900, 56000, 56100, 56200, 56300, 56400, 56480, 56500, 56600,
    56700, 56800, 56900, 57000, 57100, 57200, 57300, 57400, 57500, 57600,
    57700, 57800, 57843, 57900, 58000, 58080, 58100, 58200, 58300, 58400,
    58500, 58600, 58700, 58777, 58800, 58900, 59000, 59090, 59100, 59200,
    59300, 59400, 59500, 59600, 59700, 59800, 59898, 59900, 59999, 60000,
    60001, 60002, 60003, 60004, 60005, 60006, 60007, 60008, 60009, 60010,
    60020, 60030, 60040, 60050, 60060, 60070, 60080, 60090, 60100, 60200,
    60300, 60400, 60500, 60600, 60700, 60800, 60900, 61000, 61100, 61101,
    61102, 61200, 61201, 61202, 61203, 61204, 61205, 61206, 61207, 61208,
    61209, 61210, 61211, 61212, 61213, 61214, 61215, 61216, 61217, 61218,
    61219, 61220, 61221, 61222, 61223, 61224, 61225, 61226, 61227, 61228,
    61229, 61230, 61231, 61232, 61233, 61234, 61235, 61236, 61237, 61238,
    61239, 61240, 61241, 61242, 61243, 61244, 61245, 61246, 61247, 61248,
    61249, 61250, 62000, 62078, 63000, 63100, 64000, 64100, 65000, 65002,
    65101, 65129, 65301, 65389, 65400, 65401, 65402, 65403, 65404, 65405,
    65406, 65407, 65408, 65409, 65410, 65411, 65412, 65413, 65414, 65415,
    65416, 65417, 65418, 65419, 65420, 65421, 65422, 65423, 65424, 65425,
    65426, 65427, 65428, 65429, 65430, 65431, 65432, 65433, 65434, 65435,
    65436, 65437, 65438, 65439, 65440, 65441, 65442, 65443, 65444, 65445,
    65446, 65447, 65448, 65449, 65450, 65451, 65452, 65453, 65454, 65455,
    65456, 65457, 65458, 65459, 65460, 65461, 65462, 65463, 65464, 65465,
    65466, 65467, 65468, 65469, 65470, 65471, 65472, 65473, 65474, 65475,
    65476, 65477, 65478, 65479, 65480, 65481, 65482, 65483, 65484, 65485,
    65486, 65487, 65488, 65489, 65490, 65491, 65492, 65493, 65494, 65495,
    65496, 65497, 65498, 65499,
]

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle DB",
    2049: "NFS", 2082: "cPanel", 2083: "cPanel SSL", 2086: "WHM", 2087: "WHM SSL",
    2095: "cPanel Webmail", 2096: "cPanel Webmail SSL",
    3306: "MySQL", 3389: "RDP", 3690: "SVN", 4333: "mSQL", 4444: "Blaster",
    4848: "GlassFish", 5000: "Flask/UPnP", 5060: "SIP", 5222: "XMPP",
    5228: "Android Market", 5432: "PostgreSQL", 5555: "Android ADB",
    5631: "pcAnywhere", 5800: "VNC HTTP", 5900: "VNC", 5984: "CouchDB",
    6082: "varnish", 6379: "Redis", 6443: "HTTPS Alt",
    7001: "WebLogic", 7002: "WebLogic SSL", 8000: "HTTP Alt",
    8001: "HTTP Alt", 8080: "HTTP Proxy", 8081: "HTTP Alt",
    8086: "InfluxDB", 8088: "HTTP Alt", 8089: "Splunk", 8090: "HTTP Alt",
    8100: "HTTP Alt", 8181: "HTTP Alt", 8200: "HTTP Alt", 8222: "VMware",
    8243: "HTTPS Alt", 8280: "HTTP Alt", 8300: "HTTP Alt",
    8443: "HTTPS Alt", 8500: "HTTP Alt", 8800: "HTTP Alt",
    8880: "HTTP Alt", 8888: "HTTP Alt", 8899: "Webmin",
    8983: "Solr", 9000: "SonarQube", 9001: "HTTP Alt", 9043: "WebSphere",
    9060: "WebSphere", 9080: "WebSphere", 9090: "HTTP Alt",
    9091: "HTTP Alt", 9100: "JetDirect", 9200: "Elasticsearch",
    9300: "Elasticsearch", 9418: "Git", 9443: "HTTPS Alt",
    9600: "HTTP Alt", 9999: "HTTP Alt",
    10000: "Webmin", 10050: "Zabbix Agent", 10051: "Zabbix Server",
    11211: "Memcached", 12000: "HTTP Alt", 12345: "NetBus",
    16010: "HBase", 17000: "HTTP Alt", 18000: "HTTP Alt",
    20000: "HTTP Alt", 20720: "GlusterFS", 21000: "HTTP Alt",
    25565: "Minecraft", 27017: "MongoDB", 27018: "MongoDB",
    27019: "MongoDB", 28000: "HTTP Alt", 28015: "RethinkDB",
    30000: "HTTP Alt", 30718: "HTTP Alt", 31337: "BackOrifice",
    32764: "Router", 33060: "MySQL X", 33434: "traceroute",
    37777: "HTTP Alt", 38080: "HTTP Alt", 40000: "HTTP Alt",
    41111: "HTTP Alt", 42424: "HTTP Alt", 43333: "HTTP Alt",
    44000: "HTTP Alt", 44444: "HTTP Alt", 45000: "HTTP Alt",
    47001: "WinRM", 47544: "HTTP Alt", 47777: "HTTP Alt",
    48000: "HTTP Alt", 49000: "HTTP Alt", 49151: "HTTP Alt",
    50000: "SAP", 50070: "Hadoop", 50100: "HTTP Alt",
    54321: "HTTP Alt", 55555: "HTTP Alt", 56000: "HTTP Alt",
    57000: "HTTP Alt", 58000: "HTTP Alt", 59000: "HTTP Alt",
    60000: "HTTP Alt", 61000: "HTTP Alt", 62000: "HTTP Alt",
    63000: "HTTP Alt", 64000: "HTTP Alt", 65000: "HTTP Alt",
    65301: "PC-Duino", 65535: "HTTP Alt",
}


def _service_name(port):
    try:
        return socket.getservbyport(port)
    except (OSError, ValueError):
        pass
    return PORT_SERVICES.get(port, "Unknown")


async def _scan_port(hostname: str, port: int, timeout: float = 2.0) -> dict:
    try:
        loop = asyncio.get_running_loop()
        _, is_open = await asyncio.wait_for(
            loop.run_in_executor(None, _tcp_connect, hostname, port, timeout),
            timeout=timeout + 0.5,
        )
        return {
            "port": port,
            "service": _service_name(port),
            "state": "open" if is_open else "closed",
        }
    except asyncio.TimeoutError:
        return {"port": port, "service": _service_name(port), "state": "filtered"}
    except Exception as e:
        logger.debug("Port scan error %s:%d: %s", hostname, port, e)
        return {"port": port, "service": _service_name(port), "state": "error", "error": str(e)}


def _tcp_connect(hostname: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


async def scan_ports(hostname: str, ports: list[int] = None, timeout: float = 2.0, max_concurrency: int = 50) -> dict:
    if ports is None:
        ports = COMMON_PORTS

    semaphore = asyncio.Semaphore(max_concurrency)

    async def _scan_with_semaphore(port):
        async with semaphore:
            return await _scan_port(hostname, port, timeout)

    tasks = [_scan_with_semaphore(p) for p in ports]
    results = await asyncio.gather(*tasks)

    open_ports = [r for r in results if r["state"] == "open"]
    filtered_ports = [r for r in results if r["state"] == "filtered"]
    closed_count = sum(1 for r in results if r["state"] == "closed")

    risk_level = "low"
    if len(open_ports) > 10:
        risk_level = "high"
    elif len(open_ports) > 5:
        risk_level = "medium"

    risky_services = ["FTP", "Telnet", "SMTP", "POP3", "IMAP", "MSSQL", "MySQL", "Redis", "MongoDB", "RDP", "VNC", "SMB", "NetBIOS", "MSRPC", "Memcached"]
    high_risk_ports = [r for r in open_ports if r["service"] in risky_services]

    return {
        "hostname": hostname,
        "total_scanned": len(ports),
        "open": len(open_ports),
        "filtered": len(filtered_ports),
        "closed": closed_count,
        "open_ports": open_ports,
        "high_risk_ports": high_risk_ports,
        "risk_level": risk_level,
    }
