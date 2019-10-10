'''
    This module provide the list of nmap nse scripts name according to their category
'''


class libNmap(object):
    def __init__(self):
        self.smb_vul_nse = [
            "smb-vuln-conficker.nse", "smb-vuln-cve-2017-7494.nse", "smb-vuln-cve2009-3103.nse",
            "smb-vuln-ms06-025.nse",
            "smb-vuln-ms07-029.nse", "smb-vuln-ms08-067.nse", "smb-vuln-ms10-054.nse", "smb-vuln-ms10-061.nse",
            "smb-vuln-ms17-010.nse", "smb-vuln-regsvc-dos.nse"
        ]

        self.smb_enum_nse = [
            "smb-enum-domains.nse", "smb-enum-groups.nse", "smb-enum-processes.nse", "smb-enum-services.nse",
            "smb-enum-sessions.nse", "smb-enum-shares.nse", "smb-enum-users.nse",
        ]

