#!/usr/bin/env python3
"""
Sh4d0w - Hash Algorithm Identifier  v4.0
Usage:
    python shadow.py              # interactive mode
    python shadow.py '<hash>'     # single hash
    python shadow.py '<hash>' '<plaintext>'  # verify against plaintext
    python shadow.py --list       # show all supported families

Always wrap hashes in single quotes to prevent shell variable expansion.
"""

import re
import sys
import hashlib

GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
MAGENTA= "\033[95m"
RESET  = "\033[0m"

ASCII_ART_LINES = [
    " .d8888b. 888         d8888      888 .d8888b.               ",
    "d88P  Y88b888        d8P888      888d88P  Y88b              ",
    "Y88b.     888       d8P 888      888888    888              ",
    " \"Y888b.  88888b.  d8P  888  .d88888888    888888  888  888 ",
    "    \"Y88b.888 \"88bd88   888 d88\" 888888    888888  888  888 ",
    "      \"888888  8888888888888888  888888    888888  888  888 ",
    "Y88b  d88P888  888      888 Y88b 888Y88b  d88PY88b 888 d88P ",
    " \"Y8888P\" 888  888      888  \"Y88888 \"Y8888P\"  \"Y8888888P\"",
]

# ---------------------------------------------------------------------------
# HASHCAT MODE MAP  { display_name_keyword : hashcat_mode_number(s) }
# Used to suggest hashcat -m values alongside identification results.
# ---------------------------------------------------------------------------
HASHCAT_MODES = {
    # Raw MD / SHA
    "MD5":                              [0],
    "MD4":                              [900],
    "MD2":                              [],
    "MD6":                              [34600],
    "NTLM":                             [1000],
    "SHA-1":                            [100],
    "SHA-224":                          [1300],
    "SHA-256":                          [1400],
    "SHA-384":                          [10800],
    "SHA-512":                          [1700],
    "SHA3-224":                         [17300],
    "SHA3-256":                         [17400],
    "SHA3-384":                         [17500],
    "SHA3-512":                         [17600],
    "Keccak-224":                       [17700],
    "Keccak-256":                       [17800],
    "Keccak-384":                       [17900],
    "Keccak-512":                       [18000],
    "RIPEMD-160":                       [6000],
    "RIPEMD-320":                       [33600],
    "Whirlpool":                        [6100],
    "BLAKE2b-512":                      [600],
    "BLAKE2b-256":                      [34800],
    "BLAKE2s-256":                      [31000],
    "GOST R 34.11-94":                  [6900],
    "GOST R 34.11-2012 (Streebog-256)": [11700],
    "GOST R 34.11-2012 (Streebog-512)": [11800],
    "SM3":                              [31100],
    # Authenticated / HMAC
    "HMAC-MD5 (key = $pass)":           [50],
    "HMAC-MD5 (key = $salt)":           [60],
    "HMAC-SHA1 (key = $pass)":          [150],
    "HMAC-SHA1 (key = $salt)":          [160],
    "HMAC-SHA256 (key = $pass)":        [1450],
    "HMAC-SHA256 (key = $salt)":        [1460],
    "HMAC-SHA512 (key = $pass)":        [1750],
    "HMAC-SHA512 (key = $salt)":        [1760],
    "HMAC-RIPEMD160 (key = $pass)":     [6050],
    "HMAC-RIPEMD160 (key = $salt)":     [6060],
    "HMAC-Streebog-256":                [11750, 11760],
    "HMAC-Streebog-512":                [11850, 11860],
    "SipHash":                          [10100],
    # Password KDFs
    "bcrypt":                           [3200],
    "Argon2":                           [34000, 70000],
    "scrypt":                           [8900, 70100, 70200],
    "yescrypt":                         [],
    "PBKDF2-HMAC-MD5":                  [11900],
    "PBKDF2-HMAC-SHA1":                 [12000],
    "PBKDF2-HMAC-SHA256":               [10900],
    "PBKDF2-HMAC-SHA512":               [12100],
    "PBKDF2 (Django)":                  [10000],
    "Django SHA-1":                     [124],
    "phpass":                           [400],
    # Unix crypt
    "md5crypt":                         [500],
    "sha256crypt":                      [7400],
    "sha512crypt":                      [1800],
    "BSDi Crypt":                       [12400],
    "crypt(3) DES":                     [1500],
    "sm3crypt":                         [35100],
    "SHA-1 crypt":                      [15100],
    "AIX {smd5}":                       [6300],
    "AIX {ssha256}":                    [6400],
    "AIX {ssha512}":                    [6500],
    "AIX {ssha1}":                      [6700],
    "QNX /etc/shadow MD5":              [19000],
    "QNX /etc/shadow SHA256":           [19100],
    "QNX /etc/shadow SHA512":           [19200],
    # Windows
    "LM":                               [3000],
    "DCC / MS Cache":                   [1100],
    "DCC2 / MS Cache 2":                [2100],
    "DPAPI masterkey v1":               [15300, 15310],
    "DPAPI masterkey v2":               [15900, 15910],
    "MS-AzureSync":                     [12800],
    "Windows Hello":                    [28100],
    "Microsoft Online Account":         [33700],
    # Network protocols
    "NetNTLMv1":                        [5500],
    "NetNTLMv2":                        [5600],
    "Kerberos 5, etype 23, AS-REQ":     [7500],
    "Kerberos 5, etype 23, TGS-REP":    [13100],
    "Kerberos 5, etype 23, AS-REP":     [18200],
    "Kerberos 5, etype 17, TGS-REP":    [19600],
    "Kerberos 5, etype 18, TGS-REP":    [19700],
    "Kerberos 5, etype 17, Pre-Auth":   [19800],
    "Kerberos 5, etype 18, Pre-Auth":   [19900],
    "Kerberos 5, etype 17, AS-REP":     [32100],
    "Kerberos 5, etype 18, AS-REP":     [32200],
    "Kerberos 5, etype 17, DB":         [28800],
    "Kerberos 5, etype 18, DB":         [28900],
    "WPA-PBKDF2-PMKID+EAPOL":          [22000],
    "WPA-PMK-PMKID+EAPOL":             [22001],
    "JWT":                              [16500],
    "CRAM-MD5":                         [10200],
    "CRAM-MD5 Dovecot":                 [16400],
    "SIP digest":                       [11400],
    "TACACS+":                          [16100],
    "SNMPv3 HMAC":                      [25000, 25100, 25200, 26700, 26800, 26900, 27300],
    "IPMI2 RAKP HMAC-SHA1":             [7300],
    "IPMI2 RAKP HMAC-MD5":              [7350],
    "IKE-PSK MD5":                      [5300],
    "IKE-PSK SHA1":                     [5400],
    "iSCSI CHAP":                       [4800],
    "TOTP":                             [18100],
    "AWS Signature v4":                 [28700],
    "Flask Session Cookie":             [29100],
    "MS SNTP":                          [31300],
    "NetNTLMv1+ESS":                    [5500],
    # Databases
    "MySQL 3.x":                        [200],
    "MySQL 4.1+":                       [300],
    "MySQL CRAM (SHA1)":                [11200],
    "MySQL $A$":                        [7401],
    "Oracle H: Type (Oracle 7+)":       [3100],
    "Oracle S: Type (Oracle 11+)":      [112],
    "Oracle T: Type (Oracle 12+)":      [12300],
    "MSSQL 2000":                       [131],
    "MSSQL 2005":                       [132],
    "MSSQL 2012/2014":                  [1731],
    "PostgreSQL":                       [12],
    "PostgreSQL CRAM":                  [11100],
    "PostgreSQL SCRAM-SHA-256":         [28600],
    "MongoDB SCRAM-SHA-1":              [24100],
    "MongoDB SCRAM-SHA-256":            [24200],
    "Sybase ASE":                       [8000],
    "SQLCipher":                        [24600],
    "RACF":                             [8500],
    "RACF KDFAES":                      [14200],
    "AS/400 DES":                       [8501],
    "AS/400 SSHA1":                     [35200],
    # Application / CMS
    "WordPress / phpBB":                [400],
    "Drupal 7":                         [7900],
    "Joomla < 2.5.18":                  [11],
    "vBulletin < v3.8.5":               [2611],
    "vBulletin >= v3.8.5":              [2711],
    "MyBB 1.2+ / IPB2+":               [2811],
    "MediaWiki B type":                 [3711],
    "PrestaShop":                       [11000],
    "OpenCart":                         [13900],
    "Redmine":                          [4521],
    "PunBB":                            [4522],
    "SMF (Simple Machines)":            [121],
    "WBB3":                             [8400],
    "osCommerce":                       [21],
    "PHPS":                             [2612],
    "AuthMe sha256":                    [20711],
    "Umbraco HMAC-SHA1":                [24800],
    "Tripcode":                         [16000],
    "Empire CMS":                       [32300],
    "ColdFusion 10+":                   [12600],
    "Apache $apr1$":                    [1600],
    "LDAP SHA-1":                       [101],
    "LDAP Salted SHA-1":                [111],
    "LDAP Salted SHA-256":              [1411],
    "LDAP Salted SHA-512":              [1711],
    "RedHat 389-DS LDAP":               [10901],
    "Episerver 6.x < .NET 4":           [141],
    "Episerver 6.x >= .NET 4":          [1441],
    "nsldap":                           [101],
    "nsldaps":                          [111],
    "Django (PBKDF2-SHA256)":           [10000],
    "Atlassian (PBKDF2-HMAC-SHA1)":     [12001],
    "Apache Shiro 1 SHA-512":           [12150],
    "Ruby on Rails Restful":            [19500, 27200],
    "Anope IRC enc_sha256":             [30700],
    "Teamspeak 3":                      [28300],
    # Operating systems
    "macOS v10.4-10.6":                 [122],
    "macOS v10.7":                      [1722],
    "macOS v10.8+":                     [7100],
    "GRUB 2":                           [7200],
    "Cisco-PIX MD5":                    [2400],
    "Cisco-ASA MD5":                    [2410],
    "Cisco-IOS $8$":                    [9200],
    "Cisco-IOS $9$":                    [9300],
    "Cisco-IOS type 4 (SHA256)":        [5700],
    "Cisco-ISE (SHA256)":               [5720],
    "FortiGate (FortiOS)":              [7000],
    "FortiGate256":                     [26300],
    "Juniper NetScreen":                [22],
    "Juniper IVE":                      [501],
    "ArubaOS":                          [125],
    "Citrix NetScaler (SHA1)":          [8100],
    "Citrix NetScaler (SHA512)":        [22200],
    "Citrix NetScaler (PBKDF2)":        [33900],
    "Samsung Android":                  [5800],
    "Android FDE <= 4.3":               [8800],
    "Android FDE (Samsung DEK)":        [12900],
    "iPhone passcode":                  [26500],
    "Windows Phone 8+":                 [13800],
    "DPAPI":                            [15300],
    # Enterprise
    "SAP CODVN B (BCODE)":              [7700, 7701],
    "SAP CODVN F/G (PASSCODE)":         [7800, 7801],
    "SAP CODVN H":                      [10300, 35000],
    "PeopleSoft":                       [133],
    "PeopleSoft PS_TOKEN":              [13500],
    "Lotus Notes/Domino 5":             [8600],
    "Lotus Notes/Domino 6":             [8700],
    "Lotus Notes/Domino 8":             [9100],
    "Huawei sha1(md5)":                 [4711],
    "SolarWinds Orion":                 [21500, 21501],
    "Oracle Transportation Management": [20600],
    "RSA NetWitness sha256":            [20712],
    "OpenEdge Progress":                [26200],
    "NetIQ SSPR":                       [32000, 32010, 32020, 32030, 32040, 32050, 32060, 32070],
    "Adobe AEM":                        [32031, 32041],
    "Radmin2":                          [9900],
    "Radmin3":                          [29200],
    "ENCsecurity Datavault":            [29910, 29920, 29930, 29940],
    "SecureCRT":                        [31400],
    "Dahua Authentication MD5":         [24900],
    "KNX IP Secure":                    [25900],
    # FDE
    "BitLocker":                        [22100],
    "FileVault 2":                      [16700],
    "Apple APFS":                       [18300],
    "eCryptfs":                         [12200],
    "LUKS v1":                          [29511, 29512, 29513, 29521, 29522, 29523,
                                         29531, 29532, 29533, 29541, 29542, 29543],
    "LUKS v2":                          [34100],
    "TrueCrypt":                        [29311, 29312, 29313, 29321, 29322, 29323,
                                         29331, 29332, 29333, 29341, 29342, 29343],
    "VeraCrypt":                        [29411, 29412, 29413, 29421, 29422, 29423,
                                         29431, 29432, 29433, 29441, 29442, 29443,
                                         29451, 29452, 29453, 29461, 29462, 29463,
                                         29471, 29472, 29473, 29481, 29482, 29483],
    "BestCrypt v3":                     [23900],
    "BestCrypt v4":                     [24000],
    "DiskCryptor":                      [20011, 20012, 20013],
    "VMware VMX":                       [27400],
    "VirtualBox":                       [27500, 27600],
    "AES Crypt SHA256":                 [22400],
    "Android FDE":                      [8800],
    # Archives
    "RAR3-hp":                          [12500],
    "RAR3-p":                           [23700],
    "RAR5":                             [13000],
    "7-Zip":                            [11600],
    "WinZip AES":                       [13600],
    "PKZIP":                            [17200, 17210, 17220, 17225, 17230],
    "SecureZIP AES":                    [23001, 23002, 23003],
    "AxCrypt 1":                        [13200],
    "AxCrypt 2":                        [23500, 23600],
    "iTunes backup < 10.0":             [14700],
    "iTunes backup >= 10.0":            [14800],
    "Veeam VBK":                        [31200],
    "Kremlin Encrypt":                  [32700],
    "Stuffit5":                         [24700],
    "Android Backup":                   [18900],
    "mega.nz":                          [33400],
    "RC4":                              [33500, 33501, 33502],
    # Documents
    "MS Office 2007":                   [9400],
    "MS Office 2010":                   [9500],
    "MS Office 2013":                   [9600],
    "MS Office 2016":                   [25300],
    "MS Office <= 2003 MD5+RC4":        [9700, 9710, 9720],
    "MS Office <= 2003 SHA1+RC4":       [9800, 9810, 9820],
    "PDF 1.1-1.3":                      [10400, 10410, 10420],
    "PDF 1.4-1.6":                      [10500, 25400],
    "PDF 1.7 Level 3":                  [10600],
    "PDF 1.7 Level 8":                  [10700],
    "ODF 1.2":                          [18400],
    "ODF 1.1":                          [18600],
    "Apple Secure Notes":               [16200],
    "Apple iWork":                      [23300],
    # Password managers
    "1Password agilekeychain":          [6600],
    "1Password cloudkeychain":          [8200],
    "1Password mobilekeychain":         [31800],
    "KeePass KDBX v2/v3":              [13400],
    "KeePass KDBX v4":                  [34300],
    "LastPass":                         [6800],
    "Password Safe v2":                 [9000],
    "Password Safe v3":                 [5200],
    "Ansible Vault":                    [16900],
    "Bitwarden":                        [23400],
    "Apple Keychain":                   [23100],
    "Mozilla key3.db":                  [26000],
    "Mozilla key4.db":                  [26100],
    # Cryptocurrency
    "Bitcoin/Litecoin wallet.dat":      [11300],
    "Blockchain My Wallet V2":          [15200],
    "Blockchain My Wallet":             [12700],
    "Blockchain Legacy":                [34700],
    "Ethereum PBKDF2":                  [15600],
    "Ethereum SCRYPT":                  [15700],
    "Ethereum Pre-Sale":                [16300],
    "Electrum Salt-Type 1-3":           [16600],
    "Electrum Salt-Type 4":             [21700],
    "Electrum Salt-Type 5":             [21800],
    "MetaMask Desktop":                 [26600, 26610],
    "MetaMask Mobile":                  [31900],
    "MultiBit Classic .key":            [22500],
    "MultiBit HD":                      [22700],
    "MultiBit Classic .wallet":         [27700],
    "Bisq .wallet":                     [29800],
    "Dogechain.info":                   [32500],
    "BitShares":                        [21000],
    "Terra Station":                    [29600],
    "Stargazer Stellar":                [25500],
    "Exodus Desktop":                   [28200],
    # Private keys
    "RSA/DSA/EC/OpenSSH ($0$)":         [22911],
    "RSA/DSA/EC/OpenSSH ($6$)":         [22921],
    "RSA/DSA/EC/OpenSSH ($1/$3$)":      [22931],
    "RSA/DSA/EC/OpenSSH ($4$)":         [22941],
    "RSA/DSA/EC/OpenSSH ($5$)":         [22951],
    "JKS Java Key Store":               [15500],
    "GPG":                              [17010, 17020, 17030, 17040],
    "PKCS#8 PBKDF2-HMAC-SHA1":         [24410],
    "PKCS#8 PBKDF2-HMAC-SHA256":        [24420],
    # Checksums
    "CRC32":                            [11500],
    "CRC32C":                           [27900],
    "CRC64Jones":                       [28000],
    "MurmurHash":                       [25700],
    "MurmurHash3":                      [27800],
    "MurmurHash64A":                    [34200, 34201, 34211],
    # Misc raw
    "LM (hashcat 3000)":                [3000],
    "Half MD5":                         [5100],
    "Domain Cached Credentials (DCC)":  [1100],
    "TOTP (HMAC-SHA1)":                 [18100],
}


def suggest_hashcat(algo_name: str) -> list[int]:
    """Return a list of possible hashcat -m values for the identified algorithm."""
    modes = []
    algo_lower = algo_name.lower()
    for key, vals in HASHCAT_MODES.items():
        if key.lower() in algo_lower or algo_lower in key.lower():
            modes.extend(vals)
    # Deduplicate, preserve order
    seen = set()
    result = []
    for m in modes:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result[:8]  # Cap display at 8 suggestions


# ---------------------------------------------------------------------------
# MODULAR / PREFIXED PATTERNS  (checked first – highest specificity)
# Each entry: (regex, display_name, category)
# ---------------------------------------------------------------------------
MODULAR_PATTERNS = [

    # ── Password KDFs ────────────────────────────────────────────────────────
    (r"^\$y\$",                                 "yescrypt (Linux default, Debian 11+/Ubuntu 22.04+)",    "Password KDF"),
    (r"^\$gy\$",                                "gost-yescrypt",                                         "Password KDF"),
    (r"^\$7\$",                                 "scrypt ($7$)",                                          "Password KDF"),
    (r"^\$2[ayb]?\$\d{2}\$",                    "bcrypt ($2a$/$2b$/$2y$) — hashcat 3200", "Password KDF"),
    (r"^\$argon2(i|d|id)\$",                   "Argon2 (Argon2d / Argon2i / Argon2id)",                 "Password KDF"),
    (r"^\$s0\$",                                "scrypt ($s0$)",                                         "Password KDF"),
    (r"^pbkdf2_sha256\$",                       "Django PBKDF2-SHA256",                                  "Password KDF"),
    (r"^pbkdf2_sha512\$",                       "Django PBKDF2-SHA512",                                  "Password KDF"),
    (r"^pbkdf2_sha1\$",                         "Django PBKDF2-SHA1",                                    "Password KDF"),
    (r"^\$balloon\$",                           "Balloon Hash",                                          "Password KDF"),
    (r"^SCRYPT:",                               "scrypt (hashcat SCRYPT: format)",                       "Password KDF"),
    (r"^\$pbkdf2-sha512\$",                    "PBKDF2-HMAC-SHA512 (Python passlib)",                   "Password KDF"),
    (r"^\$pbkdf2-sha256\$",                    "PBKDF2-HMAC-SHA256 (Python passlib)",                   "Password KDF"),
    (r"^\$pbkdf2\$",                           "PBKDF2-HMAC-SHA1 (Python passlib)",                     "Password KDF"),
    (r"^sha256:\d+:",                          "PBKDF2-HMAC-SHA256 (generic / hashcat 10900)",          "Password KDF"),
    (r"^sha512:\d+:",                          "PBKDF2-HMAC-SHA512 (generic / hashcat 12100)",          "Password KDF"),
    (r"^sha1:\d+:",                            "PBKDF2-HMAC-SHA1 (generic / hashcat 12000)",            "Password KDF"),
    (r"^md5:\d+:",                             "PBKDF2-HMAC-MD5 (generic / hashcat 11900)",             "Password KDF"),
    (r"^PBKDF1:sha1:",                         "PBKDF1-SHA1 (hashcat 32900)",                           "Password KDF"),
    (r"^\$pbkdf2-hmac-sha1\$",                "NetIQ SSPR PBKDF2WithHmacSHA1",                         "Enterprise App"),
    (r"^\$pbkdf2-hmac-sha512\$",              "NetIQ SSPR PBKDF2WithHmacSHA512",                       "Enterprise App"),
    (r"^pbkdf2\(\d+,\d+,sha",                 "Web2py / passlib pbkdf2",                               "Password KDF"),
    (r"^\$bcrypt-sha256\$",                   "bcrypt(HMAC-SHA256($pass)) — passlib",                  "Password KDF"),

    # ── Unix / Linux crypt ────────────────────────────────────────────────────
    (r"^\$1\$.{1,8}\$",                        "md5crypt / Unix MD5 crypt / Cisco-IOS $1$ ($1$) — hashcat 500", "Unix/Linux Hash"),
    (r"^\$5\$",                               "sha256crypt / Unix SHA-256 crypt ($5$)",                  "Unix/Linux Hash"),
    (r"^\$6\$",                               "sha512crypt / Unix SHA-512 crypt ($6$)",                  "Unix/Linux Hash"),
    (r"^\$sm3\$",                             "sm3crypt / SM3 Unix ($sm3$)",                             "Unix/Linux Hash"),
    (r"^\$md5",                               "SunMD5 crypt",                                           "Unix/Linux Hash"),
    (r"^\$sha1\$",                            "SHA-1 crypt / Juniper NetBSD sha1crypt ($sha1$)",         "Unix/Linux Hash"),
    (r"^[a-z0-9./]{13}$",                     "crypt(3) DES (traditional Unix) — hashcat 1500",         "Unix/Linux Hash"),
    (r"^_[./0-9A-Za-z]{19}$",                "BSDi Crypt / Extended DES — hashcat 12400",               "Unix/Linux Hash"),
    (r"^\$racf\$\*",                          "RACF — hashcat 8500",                                    "Unix/Linux Hash"),
    (r"^\$racf-kdfaes\$\*",                   "RACF KDFAES — hashcat 14200",                            "Unix/Linux Hash"),
    (r"^\$as400\$des\$",                      "AS/400 DES — hashcat 8501",                              "Unix/Linux Hash"),
    (r"^\$as400\$ssha1\$",                    "AS/400 SSHA1 — hashcat 35200",                           "Unix/Linux Hash"),

    # ── AIX ───────────────────────────────────────────────────────────────────
    (r"^\{smd5\}",                            "AIX {smd5} — hashcat 6300",                              "Unix/Linux Hash"),
    (r"^\{ssha256\}",                         "AIX {ssha256} — hashcat 6400",                           "Unix/Linux Hash"),
    (r"^\{ssha512\}",                         "AIX {ssha512} — hashcat 6500",                           "Unix/Linux Hash"),
    (r"^\{ssha1\}",                           "AIX {ssha1} — hashcat 6700",                             "Unix/Linux Hash"),

    # ── QNX ──────────────────────────────────────────────────────────────────
    (r"^@m@",                                 "QNX /etc/shadow MD5 — hashcat 19000",                    "Unix/Linux Hash"),
    (r"^@s@",                                 "QNX /etc/shadow SHA256 — hashcat 19100",                  "Unix/Linux Hash"),
    (r"^@S@",                                 "QNX /etc/shadow SHA512 — hashcat 19200",                  "Unix/Linux Hash"),

    # ── Windows ───────────────────────────────────────────────────────────────
    (r"^\$DCC2\$",                            "Domain Cached Credentials 2 (DCC2) / MS Cache 2 — hashcat 2100", "Windows"),
    (r"^\$WINHELLO\$",                        "Windows Hello PIN/Password — hashcat 28100",              "Windows"),
    (r"^\$DPAPImk\$1\*",                      "DPAPI masterkey v1 — hashcat 15300/15310",                "Windows"),
    (r"^\$DPAPImk\$2\*",                      "DPAPI masterkey v2 — hashcat 15900/15910",                "Windows"),
    (r"^v1;PPH1_MD4,",                        "MS-AzureSync PBKDF2-HMAC-SHA256 — hashcat 12800",         "Windows"),
    (r"^\$MSONLINEACCOUNT\$",                 "Microsoft Online Account PBKDF2+AES256 — hashcat 33700",  "Windows"),

    # ── Network protocols ─────────────────────────────────────────────────────
    (r"^::.*:[a-f0-9]{48}:[a-f0-9]{48}:",    "NetNTLMv1 / NetNTLMv1+ESS — hashcat 5500",               "Network Protocol"),
    (r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:0101", "NetNTLMv2 — hashcat 5600",                      "Network Protocol"),
    (r"^\$krb5pa\$23\$",                      "Kerberos 5, etype 23, AS-REQ Pre-Auth — hashcat 7500",   "Network Protocol"),
    (r"^\$krb5tgs\$23\$",                     "Kerberos 5, etype 23, TGS-REP (Kerberoastable) — hashcat 13100", "Network Protocol"),
    (r"^\$krb5asrep\$23\$",                   "Kerberos 5, etype 23, AS-REP (ASREPRoast) — hashcat 18200", "Network Protocol"),
    (r"^\$krb5tgs\$17\$",                     "Kerberos 5, etype 17, TGS-REP — hashcat 19600",          "Network Protocol"),
    (r"^\$krb5tgs\$18\$",                     "Kerberos 5, etype 18, TGS-REP — hashcat 19700",          "Network Protocol"),
    (r"^\$krb5pa\$17\$",                      "Kerberos 5, etype 17, Pre-Auth — hashcat 19800",         "Network Protocol"),
    (r"^\$krb5pa\$18\$",                      "Kerberos 5, etype 18, Pre-Auth — hashcat 19900",         "Network Protocol"),
    (r"^\$krb5asrep\$17\$",                   "Kerberos 5, etype 17, AS-REP — hashcat 32100",           "Network Protocol"),
    (r"^\$krb5asrep\$18\$",                   "Kerberos 5, etype 18, AS-REP — hashcat 32200",           "Network Protocol"),
    (r"^\$krb5db\$17\$",                      "Kerberos 5, etype 17, DB — hashcat 28800",               "Network Protocol"),
    (r"^\$krb5db\$18\$",                      "Kerberos 5, etype 18, DB — hashcat 28900",               "Network Protocol"),
    (r"^\$SNMPv3\$[0-6]\$",                   "SNMPv3 HMAC (various algorithms) — hashcat 25000-27300", "Network Protocol"),
    (r"^\$cram_md5\$",                        "CRAM-MD5 — hashcat 10200",                               "Network Protocol"),
    (r"^\{CRAM-MD5\}",                        "CRAM-MD5 Dovecot — hashcat 16400",                       "Network Protocol"),
    (r"^\$sip\$\*",                           "SIP digest authentication MD5 — hashcat 11400",          "Network Protocol"),
    (r"^\$tacacs-plus\$",                     "TACACS+ — hashcat 16100",                                "Network Protocol"),
    (r"^\$sntp-ms\$",                         "MS SNTP — hashcat 31300",                                "Network Protocol"),
    (r"^\$AWS-Sig-v4\$",                      "Amazon AWS Signature Version 4 — hashcat 28700",         "Network Protocol"),
    (r"^WPA\*0[01]\*",                        "WPA-PBKDF2/PMK-PMKID+EAPOL — hashcat 22000/22001",       "Network Protocol"),
    (r"^eyJ[A-Za-z0-9+/_-]",                  "JWT (JSON Web Token) — hashcat 16500",                   "Network Protocol"),
    (r"^mojolicious=eyJ",                     "Perl Mojolicious session cookie HMAC-SHA256 — hashcat 16501", "Network Protocol"),
    (r"^pi[a-z0-9]{24}:\..*:[0-9]+:[0-9]+$", "DNSSEC (NSEC3) — hashcat 8300",                          "Network Protocol"),
    (r"^\$knx-ip-secure",                     "KNX IP Secure Device Authentication — hashcat 25900",    "Network Protocol"),
    (r"^\$flask\$|^[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$",
                                               "Flask Session Cookie or JWT-like token",                  "Network Protocol"),

    # ── Episerver ─────────────────────────────────────────────────────────────
    (r"^\$episerver\$\*0\*",                  "Episerver 6.x < .NET 4 (SHA-1) — hashcat 141",           "Application"),
    (r"^\$episerver\$\*1\*",                  "Episerver 6.x >= .NET 4 (SHA-256) — hashcat 1441",       "Application"),

    # ── Missing application prefixes ────────────────────────────────────────
    (r"^nKjiFErqK7|^[A-Za-z0-9+/]{30}:[0-9]{8}$",
                                               "Juniper NetScreen/SSG ScreenOS — hashcat 22",            "Operating System"),
    (r"^d[0-9a-f]{32}:[0-9]{7}$",             "Skype (MD5 HMAC embedded salt) — hashcat 23",             "Instant Messaging"),
    (r"^[A-Za-z0-9+/]{22}==$",               "PeopleSoft SHA-1 base64 — hashcat 133",                   "Enterprise App"),
    (r"^\$cram_md5\$[A-Za-z0-9+/=]+\$[a-f0-9]{32}$",
                                               "CRAM-MD5 (generic) — hashcat 10200",                     "Network Protocol"),
    (r"^\{CRAM-MD5\}[a-f0-9]{64}",          "CRAM-MD5 Dovecot — hashcat 16400",                       "Network Protocol"),
    (r"^\$diskcryptor\$0\*",               "DiskCryptor SHA512+XTS — hashcat 20011-20013",             "FDE"),
    (r"^\$WPA\*0[01]\*|^WPA\*0[01]\*",  "WPA-PBKDF2/PMK-PMKID+EAPOL — hashcat 22000/22001",       "Network Protocol"),
    (r"^\$SNMPv3\$0\$",                   "SNMPv3 HMAC-MD5-96/SHA1-96 combined — hashcat 25000",     "Network Protocol"),
    (r"^\$SNMPv3\$1\$",                   "SNMPv3 HMAC-MD5-96 — hashcat 25100",                      "Network Protocol"),
    (r"^\$SNMPv3\$2\$",                   "SNMPv3 HMAC-SHA1-96 — hashcat 25200",                     "Network Protocol"),
    (r"^\$SNMPv3\$3\$",                   "SNMPv3 HMAC-SHA224-128 — hashcat 26700",                  "Network Protocol"),
    (r"^\$SNMPv3\$4\$",                   "SNMPv3 HMAC-SHA256-192 — hashcat 26800",                  "Network Protocol"),
    (r"^\$SNMPv3\$5\$",                   "SNMPv3 HMAC-SHA384-256 — hashcat 26900",                  "Network Protocol"),
    (r"^\$SNMPv3\$6\$",                   "SNMPv3 HMAC-SHA512-384 — hashcat 27300",                  "Network Protocol"),
    (r"^\$bcrypt-sha256\$",               "bcrypt(HMAC-SHA256($pass)) — passlib — hashcat 30601",     "Password KDF"),
    (r"^\$2[ab]\$[0-9]{2}\$hashcat",     "WBB4 bcrypt(bcrypt) — hashcat 33800",                     "Application"),
    (r"^\$MSONLINEACCOUNT\$0\$",         "Microsoft Online Account PBKDF2+AES256 — hashcat 33700",   "Windows"),
    (r"^\$bisq\$[0-9]\*",               "Bisq .wallet scrypt — hashcat 29800",                       "Cryptocurrency"),
    (r"^\$dogechain\$0\*",              "Dogechain.info Wallet — hashcat 32500",                     "Cryptocurrency"),
    (r"^\$terra\$|^[a-zA-Z0-9+/=]{80,}wZ",
                                            "Terra Station Wallet AES256-CBC PBKDF2 — hashcat 29600",    "Cryptocurrency"),
    (r"^sha256:[a-f0-9]+:[a-f0-9]{64}$",   "Anope IRC enc_sha256 — hashcat 30700",                     "Instant Messaging"),
    (r"^\$xmpp-scram\$0\$",             "XMPP SCRAM PBKDF2-SHA1 — hashcat 23200",                   "Instant Messaging"),
    (r"^f1eff5c0|^[a-f0-9]{24}$",          "PKZIP Master Key — hashcat 20500",                         "Archive"),
    (r"^\$rc4\$40\$",                   "RC4 40-bit DropN — hashcat 33500",                         "Raw Cipher"),
    (r"^\$rc4\$72\$",                   "RC4 72-bit DropN — hashcat 33501",                         "Raw Cipher"),
    (r"^\$rc4\$104\$",                  "RC4 104-bit DropN — hashcat 33502",                        "Raw Cipher"),
    (r"^\$chacha20\$\*",               "ChaCha20 — hashcat 15400",                                  "Raw Cipher"),
    (r"^md5\$[a-zA-Z0-9]+\$[a-f0-9]{32}$",
                                            "Python Werkzeug MD5 (HMAC-MD5) — hashcat 30000",            "Application"),
    (r"^sha256\$[a-zA-Z0-9]+\$[a-f0-9]{64}$",
                                            "Python Werkzeug SHA256 (HMAC-SHA256) — hashcat 30120",      "Application"),
    (r"^sha256:[a-f0-9]{64}:[a-f0-9]{64}$",
                                            "Anope IRC enc_sha256 (alt fmt) — hashcat 30700",            "Instant Messaging"),
    (r"^\$knx-ip-secure-device",          "KNX IP Secure Device Authentication — hashcat 25900",       "Network Protocol"),
    (r"^\$ASN\$\*[12]\*",             "Apple Secure Notes — hashcat 16200",                        "Document"),
    (r"^\$vbk\$\*",                    "Veeam VBK — hashcat 31200",                                 "Archive"),
    (r"^\$kgb\$",                        "Kremlin Encrypt 3.0 / NewDES — hashcat 32700",              "Archive"),
    (r"^\$mobilekeychain\$31800",        "1Password mobilekeychain v8 — hashcat 31800",               "Password Manager"),
    (r"^PBKDF1:sha1:",                     "PBKDF1-SHA1 — hashcat 32900",                              "Password KDF"),
    (r"^\$pbkdf2-hmac-sha1\$[0-9]+\$[A-Za-z0-9+/=]+\.[a-f0-9]+",
                                            "NetIQ SSPR PBKDF2WithHmacSHA1 — hashcat 32050",            "Enterprise App"),
    (r"^\$pbkdf2-sha256\$[0-9]+\$[A-Za-z0-9]+\$",
                                            "NetIQ SSPR PBKDF2WithHmacSHA256 — hashcat 32060",          "Enterprise App"),
    (r"^\$pbkdf2-hmac-sha512\$[0-9]+\.[0-9]+",
                                            "NetIQ SSPR PBKDF2WithHmacSHA512 — hashcat 32070",          "Enterprise App"),
    (r"^\$sspr\$[0-4]\$[0-9]+\$NONE\$",
                                            "NetIQ SSPR (no salt) — hashcat 32000/32010",               "Enterprise App"),
    (r"^\$sspr\$[0-4]\$[0-9]+\$[A-Za-z0-9+/=]+\$",
                                            "NetIQ SSPR / Adobe AEM (salted) — hashcat 32020-32041",    "Enterprise App"),
    (r"^SQLCIPHER\*[12]\*",             "SQLCipher — hashcat 24600",                                 "Database"),
    (r"^\$diskcryptor\$",               "DiskCryptor SHA512+XTS — hashcat 20011-20013",              "FDE"),
    (r"^\$vmx\$0\$",                   "VMware VMX PBKDF2+AES-256-CBC — hashcat 27400",             "FDE"),
    (r"^\$vbox\$0\$",                  "VirtualBox PBKDF2+AES-XTS — hashcat 27500/27600",           "FDE"),
    (r"^\$luks\$1\$sha1\$",           "LUKS v1 SHA-1 — hashcat 29511-29513",                      "FDE"),
    (r"^\$luks\$1\$sha256\$",         "LUKS v1 SHA-256 — hashcat 29521-29523",                    "FDE"),
    (r"^\$luks\$1\$sha512\$",         "LUKS v1 SHA-512 — hashcat 29531-29533",                    "FDE"),
    (r"^\$luks\$1\$ripemd160\$",      "LUKS v1 RIPEMD-160 — hashcat 29541-29543",                 "FDE"),
    (r"^\$luks\$2\$argon2",            "LUKS v2 argon2 — hashcat 34100",                           "FDE"),
    (r"^\$truecrypt\$",                 "TrueCrypt XTS — hashcat 29311-29343",                       "FDE"),
    (r"^\$veracrypt\$",                 "VeraCrypt XTS — hashcat 29411-29483",                       "FDE"),
    (r"^\$keepass\$\*2\*",            "KeePass KDBX v2/v3 — hashcat 13400",                       "Password Manager"),
    (r"^\$keepass\$\*4\*",            "KeePass KDBX v4 — hashcat 34300",                          "Password Manager"),
    (r"^\$metamask\$",                  "MetaMask Desktop Wallet — hashcat 26600",                   "Cryptocurrency"),
    (r"^\$metamask-short\$",            "MetaMask Desktop Wallet (short) — hashcat 26610",           "Cryptocurrency"),
    (r"^\$metamaskMobile\$",            "MetaMask Mobile Wallet — hashcat 31900",                    "Cryptocurrency"),
    (r"^\$multibit\$1\*",              "MultiBit Classic .key MD5 — hashcat 22500",                 "Cryptocurrency"),
    (r"^\$multibit\$2\*",              "MultiBit HD scrypt — hashcat 22700",                        "Cryptocurrency"),
    (r"^\$multibit\$3\*",              "MultiBit Classic .wallet scrypt — hashcat 27700",           "Cryptocurrency"),
    (r"^\$stellar\$",                   "Stargazer Stellar XLM — hashcat 25500",                     "Cryptocurrency"),
    (r"^EXODUS:",                          "Exodus Desktop Wallet scrypt — hashcat 28200",              "Cryptocurrency"),
    (r"^\$sshng\$0\$",                 "RSA/DSA/EC/OpenSSH Private Key ($0$) — hashcat 22911",      "Private Key"),
    (r"^\$sshng\$6\$",                 "RSA/DSA/EC/OpenSSH Private Key ($6$) — hashcat 22921",      "Private Key"),
    (r"^\$sshng\$[13]\$",              "RSA/DSA/EC/OpenSSH Private Key ($1/$3$) — hashcat 22931",   "Private Key"),
    (r"^\$sshng\$4\$",                 "RSA/DSA/EC/OpenSSH Private Key ($4$) — hashcat 22941",      "Private Key"),
    (r"^\$sshng\$5\$",                 "RSA/DSA/EC/OpenSSH Private Key ($5$) — hashcat 22951",      "Private Key"),
    (r"^\$gpg\$\*1\*",                "GPG AES/CAST5 encrypted key — hashcat 17010-17040",         "Private Key"),
    (r"^\$PEM\$[12]\$",               "PKCS#8 Private Key PBKDF2 — hashcat 24410/24420",           "Private Key"),
    (r"^\$jksprivk\$\*",              "JKS Java Key Store Private Keys — hashcat 15500",           "Private Key"),
    (r"^\$bitcoin\$",                   "Bitcoin/Litecoin wallet.dat — hashcat 11300",               "Cryptocurrency"),
    (r"^\$blockchain\$v2\$",           "Blockchain My Wallet V2 — hashcat 15200",                   "Cryptocurrency"),
    (r"^\$blockchain\$269\$",          "Blockchain My Wallet (Legacy) — hashcat 34700",             "Cryptocurrency"),
    (r"^\$blockchain\$[0-9]",           "Blockchain My Wallet — hashcat 12700",                      "Cryptocurrency"),
    (r"^\$ethereum\$p\*",              "Ethereum PBKDF2-HMAC-SHA256 — hashcat 15600",               "Cryptocurrency"),
    (r"^\$ethereum\$s\*",              "Ethereum SCRYPT — hashcat 15700",                           "Cryptocurrency"),
    (r"^\$ethereum\$w\*",              "Ethereum Pre-Sale Wallet — hashcat 16300",                  "Cryptocurrency"),
    (r"^\$electrum\$[1-3]\*",          "Electrum Wallet Salt-Type 1-3 — hashcat 16600",             "Cryptocurrency"),
    (r"^\$electrum\$4\*",              "Electrum Wallet Salt-Type 4 — hashcat 21700",               "Cryptocurrency"),
    (r"^\$electrum\$5\*",              "Electrum Wallet Salt-Type 5 — hashcat 21800",               "Cryptocurrency"),

    # ── Application-specific ─────────────────────────────────────────────────
    (r"^\$P\$.{31}$|^\$H\$.{31}$",           "WordPress / phpBB phpass — hashcat 400",                  "Application"),
    (r"^\$S\$.{52}$",                         "Drupal 7 (Salted SHA-512) — hashcat 7900",                "Application"),
    (r"^\$apr1\$",                            "Apache MD5 crypt ($apr1$) — hashcat 1600",                "Application"),
    (r"^\{SHA\}",                             "LDAP SHA-1 / nsldap — hashcat 101",                      "Application"),
    (r"^\{SSHA\}",                            "LDAP Salted SHA-1 / nsldaps — hashcat 111",               "Application"),
    (r"^\{SSHA256\}",                         "LDAP Salted SHA-256 — hashcat 1411",                     "Application"),
    (r"^\{SSHA512\}",                         "LDAP Salted SHA-512 — hashcat 1711",                     "Application"),
    (r"^\{MD5\}",                             "LDAP MD5",                                               "Application"),
    (r"^\{crypt\}",                           "LDAP crypt",                                             "Application"),
    (r"^\{PBKDF2_SHA256\}",                   "RedHat 389-DS LDAP PBKDF2-HMAC-SHA256 — hashcat 10901",  "Application"),
    (r"^\{x-issha,\s",                        "SAP CODVN H iSSHA-1 — hashcat 10300",                    "Application"),
    (r"^\{x-isSHA512,\s",                     "SAP CODVN H isSHA512 — hashcat 35000",                   "Application"),
    (r"^\{PKCS5S2\}",                         "Atlassian PBKDF2-HMAC-SHA1 — hashcat 12001",             "Application"),
    (r"^\$PHPS\$",                            "PHPS — hashcat 2612",                                    "Application"),
    (r"^\$B\$",                               "MediaWiki B type — hashcat 3711",                        "Application"),
    (r"^sha1\$[a-f0-9]+\$[a-f0-9]{40}$",     "Django SHA-1 — hashcat 124",                             "Application"),
    (r"^\$shiro1\$SHA-512\$",                 "Apache Shiro 1 SHA-512 — hashcat 12150",                 "Application"),
    (r"^otm_sha256:",                         "Oracle Transportation Management SHA256 — hashcat 20600", "Application"),
    (r"^\$SHA\$",                             "AuthMe sha256 — hashcat 20711",                          "Application"),
    (r"^\$solarwinds\$0\$",                   "SolarWinds Orion — hashcat 21500",                       "Application"),
    (r"^\$solarwinds\$1\$",                   "SolarWinds Orion v2 — hashcat 21501",                    "Application"),
    (r"^\$radmin3\$",                         "Radmin3 — hashcat 29200",                                "Application"),
    (r"^\$encdv-pbkdf2\$",                    "ENCsecurity Datavault PBKDF2 — hashcat 29910/29920",      "Application"),
    (r"^\$encdv\$",                           "ENCsecurity Datavault MD5 — hashcat 29930/29940",         "Application"),
    (r"^S:\"Config Passphrase\"=",            "SecureCRT MasterPassphrase v2 — hashcat 31400",           "Application"),
    (r"^\$kgb\$",                             "Kremlin Encrypt 3.0 w/NewDES — hashcat 32700",            "Archive"),

    # ── Database servers ─────────────────────────────────────────────────────
    (r"^\*[a-f0-9]{40}$",                     "MySQL 4.1+ SHA-1 double hash — hashcat 300",              "Database"),
    (r"^0x0100[a-f0-9]{88}$",                 "MSSQL 2000 — hashcat 131",                               "Database"),
    (r"^0x0100[a-f0-9]{48}$",                 "MSSQL 2005 — hashcat 132",                               "Database"),
    (r"^0x0200[a-f0-9]{136}$",                "MSSQL 2012/2014 — hashcat 1731",                         "Database"),
    (r"^0x[a-f0-9]{40}$",                     "SQL Server HASHBYTES SHA-1 / Sybase ASE",                 "Database"),
    (r"^0x[a-f0-9]{64}$",                     "SQL Server HASHBYTES SHA-256 — hashcat 1400",             "Database"),
    (r"^S:[a-f0-9]{60}$",                     "Oracle 11g+ (S: type) — hashcat 112",                    "Database"),
    (r"^\$postgres\$",                        "PostgreSQL CRAM-MD5 — hashcat 11100",                    "Database"),
    (r"^\$mysqlna\$",                         "MySQL CRAM SHA1 — hashcat 11200",                        "Database"),
    (r"^\$mysql\$A\$",                        "MySQL $A$ sha256crypt — hashcat 7401",                   "Database"),
    (r"^SCRAM-SHA-256\$",                     "PostgreSQL SCRAM-SHA-256 — hashcat 28600",               "Database"),
    (r"^\$mongodb-scram\$\*0\*",              "MongoDB SCRAM-SHA-1 — hashcat 24100",                    "Database"),
    (r"^\$mongodb-scram\$\*1\*",              "MongoDB SCRAM-SHA-256 — hashcat 24200",                  "Database"),
    (r"^\$xmpp-scram\$",                      "XMPP SCRAM PBKDF2-SHA1 — hashcat 23200",                 "Database"),
    (r"^SQLCIPHER\*",                         "SQLCipher — hashcat 24600",                              "Database"),

    # ── Enterprise applications ───────────────────────────────────────────────
    (r"^[0-9]{6,12}\$[A-F0-9]{14}$",          "SAP CODVN B (BCODE) — hashcat 7700/7701",                "Enterprise App"),
    (r"^[0-9]{6,12}\$[A-F0-9]{40}$",          "SAP CODVN F/G (PASSCODE) — hashcat 7800/7801",           "Enterprise App"),
    (r"^\$sspr\$[0-4]\$",                     "NetIQ SSPR / Adobe AEM — hashcat 32000-32041",            "Enterprise App"),
    (r"^\$pbkdf2-hmac-sha1\$",                "NetIQ SSPR PBKDF2WithHmacSHA1 — hashcat 32050",           "Enterprise App"),
    (r"^\$pbkdf2-hmac-sha512\$",              "NetIQ SSPR PBKDF2WithHmacSHA512 — hashcat 32070",         "Enterprise App"),

    # ── GOST ─────────────────────────────────────────────────────────────────
    (r"^\$gost\$",                            "GOST R 34.11-94 crypt",                                   "GOST Family"),

    # ── Operating system / device specific ───────────────────────────────────
    (r"^\$fde\$",                             "Android FDE — hashcat 8800",                              "Mobile"),
    (r"^\$uido\$",                            "iPhone passcode (UID key + System Keybag) — hashcat 26500", "Mobile"),
    (r"^\$ml\$",                              "macOS v10.8+ PBKDF2-SHA512 — hashcat 7100",               "Operating System"),
    (r"^grub\.pbkdf2\.sha512\.",              "GRUB 2 — hashcat 7200",                                   "Operating System"),
    (r"^\$8\$",                               "Cisco-IOS $8$ PBKDF2-SHA256 — hashcat 9200",              "Operating System"),
    (r"^\$9\$",                               "Cisco-IOS $9$ scrypt — hashcat 9300",                    "Operating System"),

    # ── Full-Disk Encryption ─────────────────────────────────────────────────
    (r"^\$bitlocker\$",                       "BitLocker — hashcat 22100",                               "FDE"),
    (r"^\$fvde\$1\$",                         "FileVault 2 — hashcat 16700",                             "FDE"),
    (r"^\$fvde\$2\$",                         "Apple APFS — hashcat 18300",                              "FDE"),
    (r"^\$ecryptfs\$",                        "eCryptfs — hashcat 12200",                                "FDE"),
    (r"^\$luks\$1\$",                         "LUKS v1 — hashcat 29511-29543",                           "FDE"),
    (r"^\$luks\$2\$",                         "LUKS v2 — hashcat 34100",                                 "FDE"),
    (r"^\$bcve\$",                            "BestCrypt Volume Encryption — hashcat 23900/24000",        "FDE"),
    (r"^\$diskcryptor\$",                     "DiskCryptor — hashcat 20011-20013",                       "FDE"),
    (r"^\$aescrypt\$",                        "AES Crypt SHA256 — hashcat 22400",                        "FDE"),
    (r"^\$vmx\$",                             "VMware VMX PBKDF2+AES-256-CBC — hashcat 27400",           "FDE"),
    (r"^\$vbox\$",                            "VirtualBox PBKDF2+AES-XTS — hashcat 27500/27600",         "FDE"),
    (r"^\$truecrypt\$",                       "TrueCrypt XTS — hashcat 29311-29343",                     "FDE"),
    (r"^\$veracrypt\$",                       "VeraCrypt XTS — hashcat 29411-29483",                     "FDE"),

    # ── Archives ─────────────────────────────────────────────────────────────
    (r"^\$RAR3\$\*0\*",                       "RAR3-hp — hashcat 12500",                                 "Archive"),
    (r"^\$RAR3\$\*1\*",                       "RAR3-p uncompressed — hashcat 23700",                     "Archive"),
    (r"^\$rar5\$",                            "RAR5 — hashcat 13000",                                    "Archive"),
    (r"^\$7z\$",                              "7-Zip — hashcat 11600",                                   "Archive"),
    (r"^\$zip2\$",                            "WinZip AES — hashcat 13600",                              "Archive"),
    (r"^\$pkzip2\$",                          "PKZIP — hashcat 17200-17230",                             "Archive"),
    (r"^\$zip3\$",                            "SecureZIP AES — hashcat 23001-23003",                     "Archive"),
    (r"^\$axcrypt\$\*1\*",                    "AxCrypt 1 — hashcat 13200",                               "Archive"),
    (r"^\$axcrypt\$\*2\*",                    "AxCrypt 2 — hashcat 23500/23600",                         "Archive"),
    (r"^\$axcrypt_sha1\$",                    "AxCrypt 1 in-memory SHA1 — hashcat 13300",                "Archive"),
    (r"^\$itunes_backup\$\*9\*",              "iTunes backup < 10.0 — hashcat 14700",                    "Archive"),
    (r"^\$itunes_backup\$\*10\*",             "iTunes backup >= 10.0 — hashcat 14800",                   "Archive"),
    (r"^\$vbk\$",                             "Veeam VBK — hashcat 31200",                               "Archive"),
    (r"^\$ab\$",                              "Android Backup — hashcat 18900",                          "Archive"),

    # ── Documents ────────────────────────────────────────────────────────────
    (r"^\$office\$\*200[79]\*",               "MS Office 2007/2009 — hashcat 9400",                      "Document"),
    (r"^\$office\$\*2010\*",                  "MS Office 2010 — hashcat 9500",                           "Document"),
    (r"^\$office\$\*2013\*",                  "MS Office 2013 — hashcat 9600",                           "Document"),
    (r"^\$office\$\*2016\*",                  "MS Office 2016 SheetProtection — hashcat 25300",          "Document"),
    (r"^\$oldoffice\$[01]\*",                 "MS Office <= 2003 MD5+RC4 — hashcat 9700",                "Document"),
    (r"^\$oldoffice\$[34]\*",                 "MS Office <= 2003 SHA1+RC4 — hashcat 9800",               "Document"),
    (r"^\$pdf\$1\*",                          "PDF 1.1-1.3 Acrobat 2-4 — hashcat 10400",                "Document"),
    (r"^\$pdf\$2\*",                          "PDF 1.4-1.6 Acrobat 5-8 — hashcat 10500",                "Document"),
    (r"^\$pdf\$5\*5\*",                       "PDF 1.7 Level 3 Acrobat 9 — hashcat 10600",              "Document"),
    (r"^\$pdf\$5\*6\*",                       "PDF 1.7 Level 8 Acrobat 10-11 — hashcat 10700",          "Document"),
    (r"^\$odf\$\*1\*",                        "ODF 1.2 SHA-256+AES — hashcat 18400",                    "Document"),
    (r"^\$odf\$\*0\*",                        "ODF 1.1 SHA-1+Blowfish — hashcat 18600",                  "Document"),
    (r"^\$ASN\$\*",                           "Apple Secure Notes — hashcat 16200",                     "Document"),
    (r"^\$iwork\$",                           "Apple iWork — hashcat 23300",                             "Document"),

    # ── Password managers ─────────────────────────────────────────────────────
    (r"^1000:[a-f0-9]{16}:",                  "1Password agilekeychain — hashcat 6600",                  "Password Manager"),
    (r"^\$keepass\$\*2\*",                    "KeePass KDBX v2/v3 — hashcat 13400",                     "Password Manager"),
    (r"^\$keepass\$\*4\*",                    "KeePass KDBX v4 — hashcat 34300",                        "Password Manager"),
    (r"^\$mobilekeychain\$",                  "1Password mobilekeychain v8 — hashcat 31800",             "Password Manager"),
    (r"^\$ansible\$",                         "Ansible Vault — hashcat 16900",                           "Password Manager"),
    (r"^\$bitwarden\$",                       "Bitwarden — hashcat 23400",                               "Password Manager"),
    (r"^\$keychain\$\*",                      "Apple Keychain — hashcat 23100",                          "Password Manager"),
    (r"^\$mozilla\$\*3DES\*",                 "Mozilla key3.db — hashcat 26000",                         "Password Manager"),
    (r"^\$mozilla\$\*AES\*",                  "Mozilla key4.db — hashcat 26100",                         "Password Manager"),

    # ── Cryptocurrency wallets ────────────────────────────────────────────────
    (r"^\$bitcoin\$",                         "Bitcoin/Litecoin wallet.dat — hashcat 11300",             "Cryptocurrency"),
    (r"^\$blockchain\$v2\$",                  "Blockchain My Wallet V2 — hashcat 15200",                 "Cryptocurrency"),
    (r"^\$blockchain\$[0-9]",                 "Blockchain My Wallet — hashcat 12700",                    "Cryptocurrency"),
    (r"^\$blockchain\$269\$",                 "Blockchain My Wallet (Legacy) — hashcat 34700",           "Cryptocurrency"),
    (r"^\$ethereum\$p\*",                     "Ethereum PBKDF2-HMAC-SHA256 — hashcat 15600",             "Cryptocurrency"),
    (r"^\$ethereum\$s\*",                     "Ethereum SCRYPT — hashcat 15700",                         "Cryptocurrency"),
    (r"^\$ethereum\$w\*",                     "Ethereum Pre-Sale Wallet — hashcat 16300",                "Cryptocurrency"),
    (r"^\$electrum\$[1-3]\*",                 "Electrum Wallet Salt-Type 1-3 — hashcat 16600",           "Cryptocurrency"),
    (r"^\$electrum\$4\*",                     "Electrum Wallet Salt-Type 4 — hashcat 21700",             "Cryptocurrency"),
    (r"^\$electrum\$5\*",                     "Electrum Wallet Salt-Type 5 — hashcat 21800",             "Cryptocurrency"),
    (r"^\$metamask\$",                        "MetaMask Desktop Wallet — hashcat 26600",                 "Cryptocurrency"),
    (r"^\$metamask-short\$",                  "MetaMask Desktop Wallet (short) — hashcat 26610",         "Cryptocurrency"),
    (r"^\$metamaskMobile\$",                  "MetaMask Mobile Wallet — hashcat 31900",                  "Cryptocurrency"),
    (r"^\$multibit\$1\*",                     "MultiBit Classic .key — hashcat 22500",                   "Cryptocurrency"),
    (r"^\$multibit\$2\*",                     "MultiBit HD scrypt — hashcat 22700",                      "Cryptocurrency"),
    (r"^\$multibit\$3\*",                     "MultiBit Classic .wallet scrypt — hashcat 27700",         "Cryptocurrency"),
    (r"^\$bisq\$",                            "Bisq .wallet scrypt — hashcat 29800",                     "Cryptocurrency"),
    (r"^\$dogechain\$",                       "Dogechain.info Wallet — hashcat 32500",                   "Cryptocurrency"),
    (r"^\$stellar\$",                         "Stargazer Stellar XLM — hashcat 25500",                   "Cryptocurrency"),
    (r"EXODUS:",                              "Exodus Desktop Wallet scrypt — hashcat 28200",             "Cryptocurrency"),
    (r"^\$diskcryptor\$",                     "DiskCryptor SHA512+XTS — hashcat 20011-20013",             "FDE"),

    # ── Private keys ──────────────────────────────────────────────────────────
    (r"^\$sshng\$0\$",                        "RSA/DSA/EC/OpenSSH Private Key ($0$) — hashcat 22911",    "Private Key"),
    (r"^\$sshng\$6\$",                        "RSA/DSA/EC/OpenSSH Private Key ($6$) — hashcat 22921",    "Private Key"),
    (r"^\$sshng\$1\$|^\$sshng\$3\$",         "RSA/DSA/EC/OpenSSH Private Key ($1/$3$) — hashcat 22931", "Private Key"),
    (r"^\$sshng\$4\$",                        "RSA/DSA/EC/OpenSSH Private Key ($4$) — hashcat 22941",    "Private Key"),
    (r"^\$sshng\$5\$",                        "RSA/DSA/EC/OpenSSH Private Key ($5$) — hashcat 22951",    "Private Key"),
    (r"^\$jksprivk\$\*",                      "JKS Java Key Store Private Keys — hashcat 15500",         "Private Key"),
    (r"^\$gpg\$\*1\*",                        "GPG encrypted private key — hashcat 17010-17040",          "Private Key"),
    (r"^\$PEM\$[12]\$",                       "PKCS#8 Private Key PBKDF2 — hashcat 24410/24420",         "Private Key"),

    # ── BLAKE2 prefixed ───────────────────────────────────────────────────────
    (r"^\$BLAKE2\$[0-9a-f]{128}(?::[0-9]+)?","BLAKE2b-512 — hashcat 600/610/620",                       "BLAKE Family"),
    (r"^\$BLAKE2\$[0-9a-f]{64}(?::[0-9]+)?", "BLAKE2b-256 / BLAKE2s-256 — hashcat 34800/31000",         "BLAKE Family"),

    # ── Instant messaging ─────────────────────────────────────────────────────
    (r"^\$teamspeak\$3\$",                    "Teamspeak 3 channel hash — hashcat 28300",                "Instant Messaging"),
    (r"^\$telegram\$0\*",                     "Telegram Mobile App Passcode SHA-256 — hashcat 22301",    "Instant Messaging"),
    (r"^\$telegram\$1\*",                     "Telegram Desktop < v2.1.14 PBKDF2-SHA1 — hashcat 22600", "Instant Messaging"),
    (r"^\$telegram\$2\*",                     "Telegram Desktop >= v2.1.14 PBKDF2-SHA512 — hashcat 24500", "Instant Messaging"),

    # ── Misc prefixes not covered above ──────────────────────────────────────
    (r"^\$xmpp-scram\$",                      "XMPP SCRAM PBKDF2-SHA1 — hashcat 23200",                  "Instant Messaging"),
    (r"^\$DCC2\$",                            "DCC2 / MS Cache 2 — hashcat 2100",                        "Windows"),
    (r"^\$sntp-ms\$",                         "MS SNTP — hashcat 31300",                                 "Network Protocol"),
    (r"^\$uido\$",                            "iPhone passcode (UID+Keybag) — hashcat 26500",            "Mobile"),
    (r"^\$rc4\$",                             "RC4 DropN — hashcat 33500/33501/33502",                   "Raw Cipher"),
    (r"^\$chacha20\$",                        "ChaCha20 — hashcat 15400",                                "Raw Cipher"),
    (r"^\$cryptoapi\$",                       "Linux Kernel Crypto API — hashcat 14500",                 "Raw Cipher"),
    (r"^P!\$",                                "mega.nz protected link — hashcat 33400",                  "Archive"),
]

# ---------------------------------------------------------------------------
# HEX-LENGTH MAP  →  (candidates_list, category)
# ---------------------------------------------------------------------------
HEX_LENGTH_MAP = {
    8:   (["CRC32 (hashcat 11500)", "Adler-32", "FNV-1 (32-bit)", "xxHash XXH32",
           "MurmurHash3 (hashcat 27800)", "Fletcher-32", "Half-MD5"],              "Checksum / 32-bit"),
    10:  (["Stuffit5 (hashcat 24700)", "CRC-40"],                                  "Checksum"),
    16:  (["MySQL 3.x (hashcat 200)", "FNV-1 (64-bit)", "xxHash XXH64",
           "CRC64Jones (hashcat 28000)", "SipHash (64-bit)",
           "MurmurHash64A (hashcat 34200)", "Oracle 10g DES (uppercase)"],         "Checksum / Database / 64-bit"),
    22:  (["Radmin2 (hashcat 9900)"],                                              "Application"),
    32:  (["MD5 (hashcat 0)", "MD4 (hashcat 900)", "MD2", "NTLM (hashcat 1000)",
           "LM Hash (hashcat 3000)", "RIPEMD-128", "Tiger-128", "HAVAL-128",
           "xxHash XXH3-128", "CityHash128", "FarmHash128", "Skein-128",
           "FNV-1 (128-bit)", "Lotus Notes/Domino 5 (hashcat 8600)",
           "Domain Cached Credentials (hashcat 1100)"],                            "MD Family / 128-bit"),
    40:  (["SHA-1 (hashcat 100)", "SHA-0", "RIPEMD-160 (hashcat 6000)",
           "HAVAL-160", "Tiger-160", "Tiger2-160",
           "MySQL4.1/MySQL5 (hashcat 300, no asterisk)"],                          "SHA-1 / RIPEMD / Tiger"),
    48:  (["Tiger / Tiger2 (192-bit)", "HAVAL-192",
           "macOS v10.4-10.6 SHA-1+salt (hashcat 122)"],                           "Tiger / HAVAL"),
    56:  (["SHA-224 (hashcat 1300)", "SHA-512/224", "SHA3-224 (hashcat 17300)",
           "Keccak-224 (hashcat 17700)", "HAVAL-224", "Skein-224"],               "SHA-224 Family"),
    64:  (["SHA-256 (hashcat 1400)", "SHA-512/256", "SHA3-256 (hashcat 17400)",
           "Keccak-256 (hashcat 17800)", "BLAKE2s (hashcat 31000)",
           "BLAKE3", "RIPEMD-256", "GOST R 34.11-94 (hashcat 6900)",
           "GOST Streebog-256 (hashcat 11700)", "HAVAL-256", "Skein-256",
           "Snefru-256", "JH-256", "SM3 (hashcat 31100)",
           "Grøstl-256", "Luffa-256", "Shabal-256", "CubeHash-256",
           "FNV-1 (256-bit)", "HighwayHash-256", "MD6-256 (hashcat 34600)",
           "WPA/WPA2 PMK (if Wi-Fi context)"],                                    "SHA-256 / BLAKE / GOST"),
    80:  (["RIPEMD-320 (hashcat 33600)"],                                          "RIPEMD-320"),
    96:  (["SHA-384 (hashcat 10800)", "SHA3-384 (hashcat 17500)",
           "Keccak-384 (hashcat 17900)", "Skein-384", "JH-384",
           "Grøstl-384", "Shabal-384"],                                            "SHA-384 Family"),
    128: (["SHA-512 (hashcat 1700)", "SHA3-512 (hashcat 17600)",
           "Keccak-512 (hashcat 18000)", "BLAKE2b (hashcat 600)",
           "Whirlpool (hashcat 6100)", "GOST Streebog-512 (hashcat 11800)",
           "Skein-512", "JH-512", "Grøstl-512", "Luffa-512",
           "Shabal-512", "CubeHash-512", "FNV-1 (512-bit)"],                      "SHA-512 / BLAKE2b / Whirlpool"),
    160: (["HAVAL (longest)", "Skein-640", "FNV-1 (640-bit)"],                    "Extended / HAVAL"),
    256: (["FNV-1 (1024-bit)", "Skein-1024"],                                     "Large Hash / Skein"),
}

# ---------------------------------------------------------------------------
# EXTRA NON-PREFIXED PATTERNS
# ---------------------------------------------------------------------------
EXTRA_PATTERNS = [
    (r"^[A-Za-z0-9+/]{43}=$",
     "Possible iOS Keychain / KNOX hash (base64 256-bit)", "Mobile"),
    (r"^[A-F0-9]{160}$",
     "Oracle T: Type (Oracle 12+) — hashcat 12300", "Database"),
    (r"^[A-F0-9]{16}:[0-9]{10}$",
     "Oracle H: Type (Oracle 7+) DES-based — hashcat 3100", "Database"),
    (r"^[A-F0-9]{16}$",
     "Oracle 10g DES-based hash (uppercase hex 16)", "Database"),
    (r"^[a-f0-9]{32}:[a-zA-Z0-9.+/]{1,64}$",
     "Salted MD5 (hash:salt) — Magento/Joomla/osCommerce — hashcat 10/20/21", "Application"),
    (r"^[a-f0-9]{40}:[a-zA-Z0-9.+/]{1,64}$",
     "Salted SHA-1 (hash:salt) — various CMSes — hashcat 110/120", "Application"),
    (r"^[a-f0-9]{64}:[a-zA-Z0-9.+/]{1,64}$",
     "Salted SHA-256 (hash:salt) — hashcat 1410/1420", "Application"),
    (r"^[a-f0-9]{8}:[a-f0-9]{8}$",
     "CRC32 with seed — hashcat 11500", "Checksum"),
    (r"^[a-f0-9]{8}:[0-9]{8}$",
     "MurmurHash (32-bit) with seed — hashcat 25700", "Checksum"),
    (r"^[a-f0-9]{16}:[0-9]+:[0-9]+:[a-f0-9]+$",
     "SipHash — hashcat 10100", "Checksum"),
    (r"^[^:]+::[^:]+:[a-f0-9]{16}:[a-f0-9]{32}:0101",
     "NetNTLMv2 full challenge/response — hashcat 5600", "Network Protocol"),
    (r"^[a-zA-Z0-9./]{16}$",
     "Cisco-PIX MD5 or Cisco-ASA MD5 — hashcat 2400", "Operating System"),
    (r"^[a-f0-9]{32}:[a-f0-9]{12}:[a-f0-9]{12}:[a-f0-9]+$",
     "WPA-PMKID-PBKDF2 — hashcat 16800 (deprecated, use 22000)", "Network Protocol"),
    (r"^sha1\$[a-zA-Z0-9]+\$[a-f0-9]{40}$",
     "Django SHA-1 (sha1$salt$hex) — hashcat 124", "Application"),
    (r"^[a-f0-9]{22}$",
     "Radmin2 (22 hex chars) — hashcat 9900", "Application"),
    (r"^[a-f0-9]{10}$",
     "Stuffit5 or CRC-40 — hashcat 24700", "Archive"),
    (r"^[a-f0-9]{16}:[a-f0-9]{12}:[a-f0-9]{12}$",
     "WPA-PMKID (16800/22000 short form)", "Network Protocol"),
    (r"^\$rc4\$\d+\$\d+\$",
     "RC4 DropN — hashcat 33500/33501/33502", "Raw Cipher"),
    (r"^\$chacha20\$\*",
     "ChaCha20 — hashcat 15400", "Raw Cipher"),
    # DANE RFC7929 SHA-256 truncated (56 chars but less than standard SHA-224)
    (r"^[a-f0-9]{56}:[a-f0-9]{0}$",
     "DANE RFC7929 SHA2-256 — hashcat 30420", "Network Protocol"),
]

# ---------------------------------------------------------------------------
# HASH FAMILIES  (for --list display)
# ---------------------------------------------------------------------------
HASH_FAMILIES = {
    "MD Family":            ["MD2", "MD4", "MD5 (hc:0)", "MD6 (hc:34600)"],
    "SHA-1/2 Family":       ["SHA-0", "SHA-1 (hc:100)", "SHA-224 (hc:1300)",
                              "SHA-256 (hc:1400)", "SHA-384 (hc:10800)",
                              "SHA-512 (hc:1700)", "SHA-512/224", "SHA-512/256"],
    "SHA-3 / Keccak":       ["SHA3-224 (hc:17300)", "SHA3-256 (hc:17400)",
                              "SHA3-384 (hc:17500)", "SHA3-512 (hc:17600)",
                              "Keccak-224/256/384/512 (hc:17700-18000)",
                              "SHAKE128", "SHAKE256"],
    "BLAKE Family":         ["BLAKE", "BLAKE2b-512 (hc:600)", "BLAKE2b-256 (hc:34800)",
                              "BLAKE2s-256 (hc:31000)", "BLAKE3"],
    "RIPEMD Family":        ["RIPEMD", "RIPEMD-128", "RIPEMD-160 (hc:6000)",
                              "RIPEMD-256", "RIPEMD-320 (hc:33600)"],
    "Whirlpool":            ["Whirlpool (hc:6100)", "Whirlpool-T"],
    "Tiger":                ["Tiger", "Tiger2 (128/160/192-bit)"],
    "Snefru":               ["Snefru", "Snefru-2"],
    "SM3 (ShangMi)":        ["SM3 (hc:31100)", "sm3crypt (hc:35100)"],
    "GOST Family":          ["GOST R 34.11-94 (hc:6900)",
                              "Streebog-256 (hc:11700)", "Streebog-512 (hc:11800)"],
    "Other Cryptographic":  ["HAVAL-128/160/192/224/256", "PANAMA", "RadioGatún",
                              "FNV-1 (32/64/128/256/512/1024-bit)", "JH",
                              "Skein", "CubeHash", "ECOH", "FSB",
                              "Grøstl", "Luffa", "Shabal", "MD6 (hc:34600)"],
    "Checksums":            ["CRC32 (hc:11500)", "CRC32C (hc:27900)",
                              "CRC64Jones (hc:28000)", "Adler-32",
                              "Fletcher-16/32/64",
                              "xxHash (XXH32/XXH64/XXH3-64/XXH3-128)",
                              "MurmurHash (hc:25700)", "MurmurHash3 (hc:27800)",
                              "MurmurHash64A (hc:34200)", "SipHash (hc:10100)",
                              "CityHash", "FarmHash", "HighwayHash"],
    "Password KDF":         ["bcrypt (hc:3200)", "scrypt (hc:8900)", "Argon2 (hc:34000)",
                              "PBKDF1-SHA1 (hc:32900)", "PBKDF2-HMAC-MD5 (hc:11900)",
                              "PBKDF2-HMAC-SHA1 (hc:12000)", "PBKDF2-HMAC-SHA256 (hc:10900)",
                              "PBKDF2-HMAC-SHA512 (hc:12100)",
                              "Balloon Hash", "yescrypt"],
    "Unix/Linux":           ["crypt(3) DES (hc:1500)", "BSDi Crypt (hc:12400)",
                              "md5crypt (hc:500)", "sha256crypt (hc:7400)",
                              "sha512crypt (hc:1800)", "sm3crypt (hc:35100)",
                              "yescrypt", "AIX {smd5/ssha1/ssha256/ssha512}",
                              "RACF (hc:8500)", "AS/400 DES/SSHA1",
                              "QNX /etc/shadow (MD5/SHA256/SHA512)"],
    "Windows":              ["LM (hc:3000)", "NTLM (hc:1000)", "NTLMv2 (hc:5600)",
                              "DCC/MS Cache (hc:1100)", "DCC2/MS Cache 2 (hc:2100)",
                              "DPAPI v1 (hc:15300)", "DPAPI v2 (hc:15900)",
                              "MS-AzureSync (hc:12800)", "Windows Hello (hc:28100)",
                              "MS Online Account (hc:33700)"],
    "Network Protocols":    ["NetNTLMv1 (hc:5500)", "NetNTLMv2 (hc:5600)",
                              "Kerberos 5 etype 17/18/23 (hc:7500/13100/18200/19600-32200)",
                              "WPA/WPA2 PBKDF2/PMKID (hc:22000)", "JWT (hc:16500)",
                              "SNMPv3 (hc:25000-27300)", "CRAM-MD5 (hc:10200)",
                              "SIP MD5 (hc:11400)", "TACACS+ (hc:16100)",
                              "AWS Sig v4 (hc:28700)", "DNSSEC NSEC3 (hc:8300)",
                              "Flask Cookie (hc:29100)", "MS SNTP (hc:31300)"],
    "Mobile":               ["Samsung KNOX hash", "Android FDE (hc:8800)",
                              "Android FDE Samsung DEK (hc:12900)",
                              "iOS Keychain hash", "iPhone passcode (hc:26500)"],
    "Database":             ["Oracle 7+ (hc:3100)", "Oracle 10g", "Oracle 11g+ (hc:112)",
                              "Oracle 12+ (hc:12300)", "MySQL 3.x (hc:200)",
                              "MySQL 4.1+ (hc:300)", "MySQL CRAM (hc:11200)",
                              "PostgreSQL (hc:12)", "PostgreSQL SCRAM (hc:28600)",
                              "MSSQL 2000/2005/2012+ (hc:131/132/1731)",
                              "Sybase ASE (hc:8000)", "MongoDB SCRAM (hc:24100/24200)",
                              "SQLCipher (hc:24600)", "RACF (hc:8500/14200)"],
    "Application":          ["WordPress phpass (hc:400)", "Drupal 7 (hc:7900)",
                              "Joomla (hc:11)", "vBulletin (hc:2611/2711)",
                              "MyBB/IPB2 (hc:2811)", "MediaWiki B (hc:3711)",
                              "PrestaShop (hc:11000)", "OpenCart (hc:13900)",
                              "Redmine (hc:4521)", "PunBB (hc:4522)",
                              "Django SHA-1/PBKDF2 (hc:124/10000)",
                              "SAP CODVN B/F/G/H", "SolarWinds (hc:21500)",
                              "Citrix NetScaler (hc:8100/22200/33900)",
                              "FortiGate (hc:7000)", "Cisco (hc:2400/5700/9200/9300)"],
    "Enterprise Apps":      ["NetIQ SSPR (hc:32000-32070)", "Adobe AEM (hc:32031/32041)",
                              "PeopleSoft (hc:133)", "Lotus Notes 5/6/8 (hc:8600/8700/9100)",
                              "Radmin2/3 (hc:9900/29200)", "ENCsecurity Datavault",
                              "Oracle Transportation Mgmt (hc:20600)"],
    "FDE":                  ["BitLocker (hc:22100)", "FileVault 2 (hc:16700)",
                              "Apple APFS (hc:18300)", "eCryptfs (hc:12200)",
                              "LUKS v1 (hc:29511-29543)", "LUKS v2 (hc:34100)",
                              "TrueCrypt (hc:29311-29343)", "VeraCrypt (hc:29411-29483)",
                              "BestCrypt v3/v4 (hc:23900/24000)",
                              "DiskCryptor (hc:20011-20013)",
                              "VMware VMX (hc:27400)", "VirtualBox (hc:27500/27600)",
                              "AES Crypt (hc:22400)", "Android FDE (hc:8800/12900)"],
    "Archives":             ["RAR3 hp/p (hc:12500/23700)", "RAR5 (hc:13000)",
                              "7-Zip (hc:11600)", "WinZip AES (hc:13600)",
                              "PKZIP (hc:17200-17230)", "SecureZIP (hc:23001-23003)",
                              "AxCrypt 1/2 (hc:13200/23500)", "iTunes backup (hc:14700/14800)",
                              "Veeam VBK (hc:31200)", "Kremlin (hc:32700)",
                              "Android Backup (hc:18900)", "mega.nz (hc:33400)",
                              "Stuffit5 (hc:24700)", "RC4 (hc:33500-33502)"],
    "Documents":            ["MS Office 2007-2016 (hc:9400-25300)",
                              "MS Office <= 2003 (hc:9700/9800)", "PDF 1.1-1.7 (hc:10400-10700)",
                              "ODF 1.1/1.2 (hc:18400/18600)",
                              "Apple Secure Notes (hc:16200)", "Apple iWork (hc:23300)"],
    "Password Managers":    ["1Password (hc:6600/8200/31800)", "KeePass (hc:13400/34300)",
                              "LastPass (hc:6800)", "Password Safe v2/v3 (hc:9000/5200)",
                              "Ansible Vault (hc:16900)", "Bitwarden (hc:23400)",
                              "Apple Keychain (hc:23100)", "Mozilla (hc:26000/26100)"],
    "Cryptocurrency":       ["Bitcoin/Litecoin (hc:11300)", "Blockchain (hc:12700/15200/34700)",
                              "Ethereum (hc:15600/15700/16300)",
                              "Electrum (hc:16600/21700/21800)",
                              "MetaMask Desktop/Mobile (hc:26600/31900)",
                              "MultiBit (hc:22500/22700/27700)",
                              "Bisq (hc:29800)", "Dogechain (hc:32500)",
                              "Stellar XLM (hc:25500)", "Exodus (hc:28200)",
                              "Bitcoin WIF keys (hc:28501-28506)", "BitShares (hc:21000)",
                              "Terra Station (hc:29600)"],
    "Private Keys":         ["RSA/DSA/EC/OpenSSH (hc:22911-22951)",
                              "JKS Java Key Store (hc:15500)",
                              "GPG AES+SHA/CAST5 (hc:17010-17040)",
                              "PKCS#8 PBKDF2 (hc:24410/24420)"],
    "Instant Messaging":    ["Skype (hc:23)", "Telegram (hc:22301/22600/24500)",
                              "Teamspeak 3 (hc:28300)", "XMPP SCRAM (hc:23200)",
                              "Anope IRC enc_sha256 (hc:30700)"],
}


# ---------------------------------------------------------------------------
# Core identification logic
# ---------------------------------------------------------------------------

def identify(hash_string):
    """Returns (algorithm_string, confidence, warning_or_None, category)."""
    h = hash_string.strip()

    # 1. Modular / prefixed patterns — highest specificity
    for pattern, name, category in MODULAR_PATTERNS:
        if re.match(pattern, h, re.IGNORECASE):
            return name, "HIGH", None, category

    # 2. Extra non-prefixed structural patterns
    for pattern, name, category in EXTRA_PATTERNS:
        if name and re.match(pattern, h, re.IGNORECASE):
            return name, "MEDIUM", None, category

    # 3. Pure hex — use length map
    if re.match(r"^[a-f0-9]+$", h, re.IGNORECASE):
        entry = HEX_LENGTH_MAP.get(len(h))
        if entry:
            candidates, category = entry
            note = None
            if len(h) == 64:
                note = "Also possible: WPA/WPA2 PMK if derived from Wi-Fi passphrase"
            confidence = "HIGH" if len(candidates) == 1 else "MEDIUM"
            return ", ".join(candidates), confidence, note, category
        return "Unknown (unrecognised hex length)", "LOW", None, "Unknown"

    # 4. Possible shell-expansion victim
    if not h.startswith("$") and len(h) in (44, 52, 53, 31):
        return "Unknown", "LOW", "Hash may be shell-expanded — wrap in single quotes", "Unknown"

    # 5. Base64-like
    if re.match(r"^[A-Za-z0-9+/]+=*$", h) and len(h) >= 24:
        bit_len = (len(h) * 6) // 8
        return (f"Possible base64-encoded hash (~{bit_len} bytes decoded)",
                "LOW",
                "Decode from base64 first for accurate identification",
                "Base64-encoded")

    return "Unknown", "LOW", None, "Unknown"


def verify(hash_string, plaintext):
    h = hash_string.strip().lower()
    matched = []
    algos = [
        "md5", "md4", "sha1", "sha224", "sha256", "sha384", "sha512",
        "sha512_224", "sha512_256",
        "sha3_224", "sha3_256", "sha3_384", "sha3_512",
        "blake2s", "blake2b", "ripemd160", "whirlpool",
    ]
    for algo in algos:
        try:
            digest = hashlib.new(algo, plaintext.encode()).hexdigest()
            if digest == h:
                display = algo.upper().replace("_", "-").replace("SHA3", "SHA3-")
                matched.append(display)
        except (ValueError, TypeError):
            pass
    return matched


def print_banner():
    W = 78
    print(GREEN + "#" * 80 + RESET)
    print(GREEN + "#" + " " * W + "#" + RESET)
    for line in ASCII_ART_LINES:
        print(GREEN + "#" + line.center(W) + "#" + RESET)
    print(GREEN + "#" + " " * W + "#" + RESET)
    print(GREEN + "#" + "Hash Algorithm Identifier".center(W) + "#" + RESET)
    print(GREEN + "#" + "By Sh4d0wSpl01t v3.0".center(W) + "#" + RESET)
    print(GREEN + "#" + " " * W + "#" + RESET)
    print(GREEN + "#" * 80 + RESET)


def print_families():
    print(CYAN + "\n  Supported Hash Algorithm Families\n" + RESET)
    print("-" * 80)
    for family, members in HASH_FAMILIES.items():
        print(GREEN + f"  [{family}]" + RESET)
        row = []
        for m in members:
            row.append(m)
            if len(row) == 3:
                print("    " + "  |  ".join(f"{x:<28}" for x in row))
                row = []
        if row:
            print("    " + "  |  ".join(f"{x:<28}" for x in row))
        print()
    print("-" * 80)


def analyse(hash_string):
    algo, confidence, warning, category = identify(hash_string)
    short = hash_string[:60] + ("..." if len(hash_string) > 60 else "")
    conf_color = GREEN if confidence == "HIGH" else (YELLOW if confidence == "MEDIUM" else "")
    hc_modes = suggest_hashcat(algo)
    hc_str = ", ".join(str(m) for m in hc_modes) if hc_modes else "N/A"
    print(f"\n  Hash      : {short}")
    print(GREEN + f"  Algorithm : {algo}" + RESET)
    print(f"  Category  : {CYAN}{category}{RESET}")
    print(f"  Confidence: {conf_color}{confidence}{RESET}")
    if hc_modes:
        print(f"  Hashcat -m: {MAGENTA}{hc_str}{RESET}")
    if warning:
        print(f"  {YELLOW}Warning{RESET}   : {warning}")
    print()


def interactive():
    print_banner()
    print()
    print("-" * 80)
    print(f"  Commands: {GREEN}hash{RESET} to identify  |  {GREEN}list{RESET} to show families  |  {GREEN}quit{RESET} to exit")
    print("-" * 80)
    while True:
        try:
            raw = input(GREEN + "\n  HASH: " + RESET).strip()
            if not raw:
                continue
            cmd = raw.lower()
            if cmd in ("quit", "exit", "q"):
                print("\n  Goodbye.\n")
                break
            if cmd in ("list", "families", "help"):
                print_families()
                continue
            analyse(raw)
            print("-" * 80)
        except KeyboardInterrupt:
            print("\n\n  Goodbye.\n")
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        interactive()
    elif sys.argv[1] in ("--list", "-l", "list"):
        print_families()
    else:
        h = sys.argv[1]
        plaintext = sys.argv[2] if len(sys.argv) > 2 else None
        algo, confidence, warning, category = identify(h)
        short = h[:60] + ("..." if len(h) > 60 else "")
        if plaintext and re.match(r"^[a-f0-9]+$", h.strip(), re.IGNORECASE):
            matched = verify(h, plaintext)
            if matched:
                algo = ", ".join(matched) + " (verified)"
                confidence = "HIGH"
        hc_modes = suggest_hashcat(algo)
        hc_str = ", ".join(str(m) for m in hc_modes) if hc_modes else "N/A"
        print(f"Hash      : {short}")
        print(GREEN + f"Algorithm : {algo}" + RESET)
        print(f"Category  : {CYAN}{category}{RESET}")
        print(f"Confidence: {confidence}")
        if hc_modes:
            print(MAGENTA + f"Hashcat -m: {hc_str}" + RESET)
        if warning:
            print(YELLOW + f"Warning   : {warning}" + RESET)
