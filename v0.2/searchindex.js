Search.setIndex({"docnames": ["docs/contributing", "docs/index", "docs/introduction", "docs/memory/index", "docs/memory/memory-qos", "docs/memory/memtierd", "docs/resource-policy/configuration", "docs/resource-policy/developers-guide/architecture", "docs/resource-policy/developers-guide/cpu-allocator", "docs/resource-policy/developers-guide/e2e-test", "docs/resource-policy/developers-guide/index", "docs/resource-policy/developers-guide/testing", "docs/resource-policy/developers-guide/unit-test", "docs/resource-policy/index", "docs/resource-policy/installation", "docs/resource-policy/introduction", "docs/resource-policy/policy/balloons", "docs/resource-policy/policy/index", "docs/resource-policy/policy/topology-aware", "docs/resource-policy/setup"], "filenames": ["docs/contributing.md", "docs/index.md", "docs/introduction.md", "docs/memory/index.md", "docs/memory/memory-qos.md", "docs/memory/memtierd.md", "docs/resource-policy/configuration.md", "docs/resource-policy/developers-guide/architecture.md", "docs/resource-policy/developers-guide/cpu-allocator.md", "docs/resource-policy/developers-guide/e2e-test.md", "docs/resource-policy/developers-guide/index.md", "docs/resource-policy/developers-guide/testing.md", "docs/resource-policy/developers-guide/unit-test.md", "docs/resource-policy/index.md", "docs/resource-policy/installation.md", "docs/resource-policy/introduction.md", "docs/resource-policy/policy/balloons.md", "docs/resource-policy/policy/index.md", "docs/resource-policy/policy/topology-aware.md", "docs/resource-policy/setup.md"], "titles": ["Contributing", "Welcome to NRI Plugins documentation", "Introduction", "Memory plugins", "Memory QoS NRI plugin", "Memtierd NRI plugin", "Dynamic Configuration", "Architecture", "CPU Allocator", "End-to-End tests", "Developer\u2019s Guide", "Testing", "Unit tests", "Resource Policy Plugins", "Installation", "Introduction", "Balloons Policy", "Policies", "Topology-Aware Policy", "Setup and Usage"], "terms": {"pleas": 0, "us": [0, 2, 4, 5, 6, 7, 9, 14, 16, 18, 19], "github": [0, 1, 4, 5, 14], "infrastructur": 0, "nri": [0, 2, 3, 6, 7, 8, 9, 13, 14, 15, 16, 18], "plugin": [0, 2, 6, 7, 14, 15, 19], "pull": [0, 14, 18], "request": [0, 7, 8, 15, 16], "code": 0, "bug": 0, "fix": 0, "you": [0, 6, 9, 14, 16, 18, 19], "want": [0, 9, 19], "discuss": 0, "your": [0, 14], "idea": 0, "term": [0, 8], "open": 0, "issu": 0, "report": [0, 9], "new": [0, 7, 16], "featur": [0, 8, 14], "ani": [0, 5, 6, 7, 14, 16, 18, 19], "other": [0, 4, 5, 6, 7, 8, 14, 16, 18], "topic": 0, "relat": [0, 7, 14, 16], "For": [0, 2, 4, 7, 8, 9, 14, 18, 19], "actual": [0, 4, 14], "node": [0, 2, 4, 5, 6, 9, 14, 16, 18, 19], "resourc": [0, 1, 2, 4, 6, 8, 9, 14, 15, 16, 17, 18], "interfac": [0, 2, 7], "api": [0, 7, 15], "see": [0, 4, 5, 6, 8, 16, 19], "repositori": [0, 1, 14], "introduct": [1, 13], "polici": [1, 2, 5, 6, 8, 9, 14, 15], "instal": [1, 4, 5, 9, 13, 16, 19], "setup": [1, 9, 13, 16, 18], "usag": [1, 4, 13, 16, 18], "dynam": [1, 7, 13, 16, 18], "configur": [1, 3, 7, 8, 9, 13, 14, 15, 17], "develop": [1, 3, 7, 13], "": [1, 3, 7, 9, 13, 14, 16, 18], "guid": [1, 3, 13], "memori": [1, 5, 7, 8, 9, 16], "qo": [1, 3, 18], "memtierd": [1, 3], "contribut": 1, "project": [1, 14], "The": [2, 5, 6, 7, 8, 9, 14, 15, 16, 17, 18, 19], "i": [2, 4, 5, 6, 7, 8, 9, 14, 15, 16, 18, 19], "collect": [2, 7, 14], "base": [2, 7, 16, 18], "manag": [2, 5, 9, 14, 16], "variou": [2, 7, 14, 18], "aspect": [2, 7], "pod": [2, 4, 5, 7, 14, 16], "contain": [2, 4, 5, 6, 7, 9, 14, 15], "life": 2, "cycl": 2, "exampl": [2, 6, 8, 9, 14], "can": [2, 6, 7, 9, 14, 16, 18, 19], "modifi": [2, 4, 5, 7, 14], "alloc": [2, 4, 5, 7, 10, 13, 15, 16, 17], "depend": [2, 6, 7, 15, 18], "avail": [2, 6, 9, 14, 15, 16, 18, 19], "system": [2, 5, 7, 8, 9, 14, 15, 16, 18], "workload": [3, 7, 8, 16, 17, 18], "secur": 3, "thi": [4, 5, 7, 9, 14, 16, 18, 19], "add": [4, 7, 14], "two": [4, 6, 8, 9, 14, 16, 17, 18], "method": [4, 14], "control": [4, 14, 16, 17, 18, 19], "cgroup": [4, 5], "v2": [4, 5], "paramet": [4, 8], "direct": [4, 7], "There": [4, 6, 9, 15, 16, 18], "ar": [4, 6, 7, 8, 9, 14, 15, 16, 17, 18, 19], "calcul": [4, 18], "same": [4, 5, 7, 9, 16, 18, 19], "wai": [4, 7, 17, 18], "all": [4, 5, 7, 8, 9, 16, 18], "belong": [4, 5, 6, 16, 18], "specif": [4, 5, 6, 7, 8, 14, 18], "defin": [4, 5, 7, 9, 16, 18], "yaml": [4, 5, 14, 16, 18, 19], "set": [4, 5, 6, 7, 13, 14, 15, 16, 18], "default": [4, 5, 6, 9, 14, 16, 18, 19], "io": [4, 5, 6, 14, 16, 18], "silver": 4, "overrid": [4, 5], "c0": [4, 5], "bronz": 4, "remov": [4, 6, 7, 14, 16, 19], "from": [4, 5, 6, 7, 16, 18, 19], "c1": [4, 5, 18], "given": [4, 16, 18], "follow": [4, 5, 7, 14, 16, 18], "affect": [4, 5, 7, 16, 18], "swap": [4, 5], "max": [4, 5, 16], "high": [4, 7, 8, 16, 18], "oom": [4, 18], "group": [4, 6, 9, 18], "never": [4, 18], "noswap": 4, "0": [4, 9, 14, 16, 18], "process": [4, 5, 7, 14], "get": [4, 7, 9, 14, 18, 19], "kill": [4, 16], "do": [4, 5, 7, 16, 18, 19], "whole": [4, 18], "list": [4, 5, 14, 16, 18, 19], "map": [4, 5, 8], "kei": [4, 5, 9, 14, 18], "valu": [4, 5, 9, 14, 16, 18], "name": [4, 5, 6, 7, 9, 14, 16, 18, 19], "string": [4, 5, 14, 18], "match": [4, 5, 16, 18], "swaplimitratio": 4, "1": [4, 5, 9, 14, 16, 18], "minimum": [4, 16], "ratio": 4, "limit": [4, 16], "when": [4, 5, 9, 14, 16, 18, 19], "consumpt": 4, "reach": 4, "adjust": [4, 7], "watermark": 4, "unifiedannot": 4, "oci": 4, "linux": [4, 9, 14], "field": 4, "file": [4, 5, 7, 14, 18, 19], "whose": [4, 16], "allow": [4, 5, 7, 16, 17], "If": [4, 5, 7, 8, 9, 14, 16, 18, 19], "thei": [4, 18], "impli": [4, 18], "5": [4, 5, 7, 18], "2": [4, 5, 7, 9, 16, 18], "belog": 4, "ha": [4, 5, 7, 8, 16, 18, 19], "half": 4, "its": [4, 6, 7, 14, 16, 18], "next": [4, 16], "caus": [4, 7, 16, 18], "kernel": [4, 16, 18], "out": [4, 5, 16, 18], "correspond": [4, 7, 18, 19], "amount": [4, 5, 18], "In": [4, 7, 9, 14, 16, 18], "word": [4, 18], "close": [4, 8, 18], "most": [4, 7, 16, 18], "data": [4, 5, 7, 14, 18], "store": [4, 5, 18], "ram": [4, 9], "keep": [4, 7, 16], "up": [4, 7, 13, 14, 18], "80": 4, "directli": [4, 7], "instanc": [4, 7, 14, 18, 19], "enabl": [4, 5, 8, 14, 16, 18], "containerd": [4, 5, 9, 14, 15, 19], "v1": [4, 5, 14], "7": [4, 5, 14], "etc": [4, 5], "config": [4, 5, 6, 7, 14, 16, 19], "toml": [4, 5], "disabl": [4, 5, 8, 19], "fals": [4, 5, 14, 16, 18], "disable_connect": [4, 5], "plugin_config_path": [4, 5], "conf": [4, 5], "d": [4, 5], "plugin_path": [4, 5], "opt": [4, 5, 18], "plugin_registration_timeout": [4, 5], "plugin_request_timeout": [4, 5], "socket_path": [4, 5], "var": [4, 5, 9], "sock": [4, 5], "cd": [4, 5, 9, 14], "cmd": [4, 5], "go": [4, 5, 7, 9], "sampl": [4, 5, 6, 16], "idx": [4, 5], "40": [4, 5], "vv": [4, 5], "kubectl": [4, 5, 14], "creat": [4, 5, 7, 9, 14, 16, 18], "f": [4, 5, 14], "e2": [4, 5, 9], "statu": [4, 5, 9, 14], "dd": [4, 5], "each": [4, 5, 7, 8, 9, 14, 15, 16, 18], "pid": [4, 5], "pidof": [4, 5], "grep": [4, 5], "vmswap": [4, 5], "proc": [4, 5], "done": [4, 5, 18], "com": [4, 5, 14], "delv": [4, 5], "dlv": [4, 5], "latest": [4, 5], "exec": [4, 5], "break": [4, 5], "createcontain": [4, 5], "continu": [4, 5], "an": [4, 5, 7, 9, 14, 16, 18, 19], "imag": [4, 5, 14], "import": [4, 5, 14], "rm": [4, 5, 8], "rf": [4, 5], "make": [4, 5, 7, 8, 9, 12, 18], "clean": 4, "image_vers": [4, 5], "devel": [4, 5], "ctr": [4, 5], "n": [4, 5, 14], "k8": [4, 5, 18], "tar": [4, 5], "deploy": [4, 5, 14, 19], "kubernet": [5, 7, 14, 16, 18, 19], "attribut": [5, 16], "launch": 5, "track": [5, 7], "specifi": [5, 14, 16, 18], "annot": [5, 7, 16], "idl": [5, 16, 18], "work": [5, 19], "size": [5, 9, 16], "associ": [5, 7, 8, 14], "allowswap": 5, "true": [5, 14, 16, 18, 19], "o": [5, 14, 15, 18, 19], "disallow": 5, "what": [5, 18], "written": 5, "memtierdconfig": 5, "templat": [5, 14], "which": [5, 7, 14, 15, 16, 18, 19], "variabl": [5, 9, 19], "replac": [5, 14], "cgroup2_abs_path": 5, "absolut": 5, "path": [5, 14], "directori": [5, 9, 14], "ag": [5, 14], "intervalm": 5, "10000": 5, "pidwatch": 5, "swapoutm": 5, "tracker": 5, "idlepag": 5, "pagesinregion": 5, "512": 5, "maxcountperregion": 5, "scanintervalm": 5, "mover": 5, "20": 5, "bandwidth": [5, 18], "50": 5, "sure": [5, 7], "decid": [5, 7, 16, 18], "should": [5, 7, 16, 18], "mean": [5, 16, 18], "find": [5, 14], "been": [5, 8], "access": [5, 7, 16, 18], "10": [5, 18], "second": [5, 18], "m": 5, "interv": 5, "more": [5, 6, 8, 9, 16, 17, 18], "than": [5, 7, 16, 18], "mb": 5, "refer": [5, 14, 18], "document": [5, 6, 8], "option": [5, 14, 16, 18, 19], "To": [5, 14, 18], "host": [5, 14], "gobin": 5, "usr": 5, "local": [5, 14, 16, 18, 19], "bin": 5, "intel": [5, 18], "v": 5, "output": [5, 14], "even": [5, 16], "verbos": [5, 16], "under": [5, 9, 14, 18], "tmp": 5, "namespac": [5, 14, 16], "variant": 5, "give": [5, 9, 18], "both": [5, 7, 9, 18, 19], "log": [5, 7, 9, 13, 16], "kube": [5, 14, 16, 18], "need": [5, 7, 14, 18, 19], "privileg": 5, "order": [5, 8, 9, 16, 17], "activ": [5, 7, 8, 16], "move": [5, 18], "page": 5, "therefor": [5, 9, 18], "onli": [5, 8, 9, 14, 16, 18, 19], "user": [5, 7, 14, 16, 17, 18], "must": [5, 9, 14], "configmap": [5, 6, 7, 14, 16], "command": [5, 9, 14, 16, 19], "execut": [5, 9], "mode": [5, 7], "daemon": 6, "monitor": 6, "primari": 6, "one": [6, 7, 8, 9, 14, 16, 18], "secondari": 6, "whether": [6, 15, 18], "alwai": [6, 14, 16, 18], "take": [6, 7, 8, 18], "preced": [6, 18, 19], "over": [6, 16, 18], "node_nam": 6, "group_nam": 6, "assign": [6, 7, 18], "label": [6, 7, 18], "delet": [6, 7, 9, 14], "spec": [6, 18], "inform": 6, "later": [7, 19], "rp": 7, "plug": 7, "provid": [7, 14, 17, 18, 19], "runtim": [7, 9, 14, 15, 19], "mai": [7, 8, 16], "alter": [7, 15, 18], "state": [7, 16], "run": [7, 12, 14, 15, 16, 18, 19], "whenev": [7, 16, 18], "receiv": 7, "result": [7, 16, 18], "chang": [7, 9, 16, 18, 19], "creation": [7, 18], "updat": [7, 14, 19], "built": [7, 8], "algorithm": [7, 18], "decis": [7, 16], "about": [7, 18, 19], "how": [7, 15, 18, 19], "just": [7, 14, 18], "intern": 7, "abstract": 7, "record": 7, "mani": [7, 16], "These": [7, 18, 19], "includ": [7, 14, 16], "although": [7, 18], "static": [7, 16, 19], "prefer": [7, 8, 16], "cluster": [7, 9, 14, 19], "crd": 7, "itself": 7, "interact": 7, "plane": [7, 14], "through": [7, 14], "perform": [7, 8, 15, 18], "behalf": 7, "function": [7, 9, 18], "push": [7, 18, 19], "extern": 7, "capac": [7, 18], "taint": [7, 14], "grpc": 7, "server": [7, 18], "act": [7, 18], "client": 7, "low": [7, 8, 16, 18], "level": 7, "conveni": 7, "plumb": 7, "addition": [7, 18, 19], "stock": 7, "come": 7, "scheme": 7, "event": 7, "pipelin": 7, "addit": [7, 19], "typic": [7, 18], "within": [7, 16, 18], "basic": [7, 18], "flow": 7, "It": [7, 14, 15], "pass": [7, 9, 19], "necessari": 7, "sub": [7, 18], "phase": 7, "serial": 7, "being": [7, 18], "point": 7, "time": [7, 18], "A": [7, 16, 18], "doe": [7, 8, 16, 18], "let": 7, "bypass": 7, "hand": [7, 16, 18], "off": [7, 18, 19], "relai": 7, "respons": 7, "back": 7, "b": 7, "intercept": 7, "lock": 7, "look": 7, "object": [7, 9, 14], "consequ": 7, "proxi": 7, "step": [7, 14], "6": 7, "otherwis": [7, 9, 18], "invok": 7, "post": 7, "pend": 7, "domain": 7, "clear": 7, "marker": 7, "send": 7, "releas": [7, 14, 18], "type": [7, 8, 14, 16, 18], "engag": 7, "call": [7, 9], "handler": 7, "share": 7, "storag": 7, "locat": 7, "known": 7, "well": [7, 18], "save": [7, 9, 16], "perman": 7, "filesystem": 7, "restor": 7, "across": [7, 16], "restart": 7, "queri": 7, "mechan": 7, "simpli": [7, 14], "accord": [7, 14, 16, 18], "abil": 7, "enforc": 7, "first": [7, 9, 16, 18, 19], "have": [7, 8, 9, 14, 16, 18, 19], "anyth": 7, "accordingli": 7, "howev": [7, 14, 18, 19], "instead": [7, 18], "assum": [7, 19], "caller": 7, "proper": 7, "protect": 7, "place": [7, 16, 18], "against": [7, 18], "concurr": 7, "read": 7, "write": 7, "unsolicit": 7, "iow": [7, 18], "handl": [7, 18], "backend": 7, "inject": 7, "loop": 7, "callback": 7, "argument": 7, "properli": [7, 18], "rest": 7, "care": [7, 18, 19], "detail": [7, 8, 14, 15, 16, 18], "dispatch": 7, "gather": 7, "period": [7, 18], "evalu": [7, 18], "determin": [7, 18], "optim": [7, 8, 18], "current": [7, 8, 9, 14, 16, 17, 18, 19], "attempt": 7, "rebalanc": 7, "realloc": 7, "deem": 7, "possibl": [7, 8, 18, 19], "capabl": 7, "multipl": [7, 18], "tier": [7, 18], "dram": [7, 18], "pmem": [7, 18], "combin": [7, 18], "fine": 7, "grain": 7, "comput": [7, 18], "distribut": [7, 9], "hook": 7, "fill": [7, 16], "edit": [7, 19], "copi": [7, 9, 18], "separ": [8, 18], "compon": [8, 14], "help": [8, 9, 16], "educ": 8, "core": [8, 9, 16, 18], "util": 8, "tri": 8, "hardwar": [8, 15, 16], "aim": 8, "pack": [8, 16], "minim": 8, "latenc": [8, 18], "between": [8, 16, 18], "also": [8, 18], "automat": [8, 18], "detect": [8, 18], "support": [8, 9, 18, 19], "prioriti": [8, 18], "intel_pst": 8, "scale": 8, "driver": 8, "subsystem": 8, "divid": [8, 18], "three": [8, 18], "class": [8, 16, 18], "e": 8, "normal": [8, 9, 16, 18], "choos": [8, 14, 16], "certain": [8, 9, 18], "preserv": 8, "profil": 8, "pp": 8, "frequenc": [8, 16], "bf": 8, "turbo": [8, 16], "tf": 8, "power": [8, 16], "cp": 8, "parameter": 8, "flag": [8, 14, 19], "examin": 8, "servic": 8, "highest": [8, 16], "clo": 8, "lowest": 8, "middl": 8, "inact": 8, "higher": [8, 19], "guarante": [8, 18], "effect": [8, 14, 16, 18, 19], "epp": 8, "energi": 8, "rel": 8, "correspondingli": 8, "mark": [8, 18], "docker": 9, "vagrant": 9, "run_test": 9, "sh": 9, "suit": 9, "select": [9, 16, 18], "testnn": 9, "definit": [9, 16, 18], "appli": [9, 14, 15, 18, 19], "script": 9, "unless": [9, 16, 18], "alreadi": [9, 16, 18, 19], "singl": [9, 16, 18], "deploi": [9, 16], "daemonset": [9, 14, 19], "bash": 9, "helper": 9, "observ": 9, "softwar": 9, "tear": 9, "down": 9, "final": [9, 18], "stop": 9, "fast": 9, "verdict": 9, "fail": 9, "exit": 9, "zero": [9, 17], "vm_name": 9, "environ": [9, 14, 19], "construct": 9, "vm": 9, "destroi": [9, 16], "numa": [9, 16, 18], "ignor": 9, "json": 9, "arrai": 9, "mem": 9, "0g": 9, "nvmem": 9, "non": [9, 18], "volatil": 9, "number": [9, 16, 18], "cpu": [9, 10, 13, 14, 16], "thread": [9, 16], "die": [9, 16, 18], "di": [9, 16, 18], "packag": [9, 16], "4": [9, 16, 18], "per": [9, 18], "4g": 9, "my2x4": 9, "32": 9, "total": 9, "socket": [9, 16, 18], "And": 9, "16g": 9, "nvram": 9, "mynvram": 9, "outdir": 9, "case": [9, 18, 19], "standard": 9, "n4c16": 9, "gener": [9, 14, 18], "fedora37": 9, "would": [9, 16, 18], "indic": [9, 18], "four": 9, "16": 9, "fedora": 9, "37": 9, "timestamp": 9, "architectur": [10, 13, 18], "test": [10, 13], "unit": 11, "end": [11, 18], "prerequisit": 13, "helm": 13, "chart": 13, "uninstal": 13, "manual": 13, "debug": 13, "topologi": [13, 16, 17], "awar": [13, 15, 17], "balloon": [13, 17], "we": 14, "demonstr": 14, "fall": 14, "outlin": 14, "here": [14, 19], "regardless": 14, "chosen": 14, "customresourcedefinit": 14, "rbac": 14, "At": 14, "least": [14, 16], "version": [14, 18], "instruct": 14, "dure": [14, 16, 18], "patchruntimeconfig": 14, "init": 14, "turn": [14, 19], "after": [14, 18], "proce": 14, "cri": [14, 15, 18, 19], "26": 14, "24": 14, "3": [14, 16], "so": [14, 18], "repo": 14, "http": [14, 16], "ensur": 14, "ad": [14, 16, 18], "desir": 14, "wish": 14, "custom": 14, "tabl": 14, "below": [14, 16, 18], "describ": 14, "befor": [14, 19], "either": [14, 18, 19], "along": [14, 18], "note": [14, 18, 19], "crucial": 14, "manifest": 14, "cat": 14, "eof": 14, "mypath": 14, "toler": 14, "role": 14, "oper": [14, 18], "exist": [14, 16, 18], "noschedul": 14, "flexibl": 14, "serv": 14, "accur": 14, "reflect": [14, 18], "verifi": 14, "successfulli": [14, 19], "readi": 14, "TO": 14, "date": 14, "selector": 14, "4m33": 14, "That": [14, 19], "now": 14, "enough": [14, 16, 18], "present": [14, 16, 18], "overview": 14, "own": 14, "descript": 14, "ghcr": 14, "tag": [14, 18], "unstabl": 14, "pullpolici": 14, "500m": 14, "512mi": 14, "qouta": 14, "hostport": 14, "8891": [14, 16], "metric": 14, "port": 14, "expos": [14, 18], "reservedresourc": [14, 16, 18], "750m": [14, 18], "initimag": 14, "250m": 14, "100mi": 14, "outputdir": 14, "empti": [14, 18], "10m": 14, "tool": 14, "clone": 14, "machin": [14, 18], "git": 14, "navig": 14, "kustom": 14, "build": [14, 18], "overlai": 14, "kutom": 14, "connect": 15, "implement": [15, 16, 18], "via": 15, "main": [15, 18], "purpos": [15, 18], "differ": [15, 16, 18], "goal": 15, "mind": 15, "strategi": 15, "extra": [15, 16, 18], "action": 15, "placement": [16, 18], "disjoint": [16, 18], "pool": 16, "inflat": 16, "deflat": 16, "min": 16, "uncor": 16, "instanti": 16, "everi": 16, "exactli": 16, "logic": [16, 18], "lifetim": 16, "opposit": 16, "fit": [16, 18], "reconfigur": [16, 19], "pincpu": [16, 18], "pin": [16, 18], "cannot": 16, "pinmemori": [16, 18], "closest": [16, 18], "warn": 16, "due": [16, 18], "error": 16, "situat": [16, 18], "consid": [16, 18], "switch": 16, "idlecpuclass": 16, "those": [16, 18], "reservedpoolnamespac": [16, 18], "wildcard": [16, 18], "special": [16, 18], "reserv": 16, "allocatortopologybalanc": 16, "free": [16, 18], "spread": 16, "reduc": 16, "interfer": 16, "fulli": [16, 18], "load": 16, "tightli": 16, "larg": [16, 18], "portion": 16, "enter": 16, "deep": 16, "balloontyp": 16, "overridden": 16, "minballoon": 16, "maxballoon": 16, "maximum": [16, 18], "co": 16, "maxcpu": 16, "larger": [16, 18], "unlimit": 16, "mincpu": 16, "less": 16, "cpuclass": 16, "preferspreadingpod": 16, "preferpernamespaceballoon": 16, "On": [16, 18], "preferr": 16, "prefernewballoon": 16, "exclus": 16, "long": [16, 18], "ones": [16, 18, 19], "shareidlecpusinsam": 16, "reshar": 16, "common": [16, 18], "anywher": 16, "allocatorprior": 16, "none": 16, "resiz": 16, "pre": 16, "By": 16, "minfreq": 16, "maxfreq": 16, "uncoreminfreq": 16, "uncoremaxfreq": 16, "lowpow": 16, "quad": 16, "800": 16, "3600": 16, "3000": 16, "2000": 16, "2400": 16, "complet": 16, "bt": 16, "container_nam": 16, "last": 16, "explicit": 16, "export": 16, "instrument": 16, "global": [16, 18, 19], "cpuset": 16, "line": [16, 19], "curl": 16, "silent": 16, "localhost": 16, "httpendpoint": 16, "prometheusexport": 16, "logger": 16, "nearli": 17, "evenli": 17, "avoid": [17, 18], "noisi": 17, "neighbor": 17, "problem": 17, "grade": 18, "peripher": 18, "form": 18, "rather": 18, "complex": 18, "network": 18, "togeth": 18, "bu": 18, "hierarchi": 18, "interconnect": 18, "vari": 18, "greatli": 18, "effici": 18, "transfer": 18, "them": 18, "align": 18, "inher": 18, "properti": 18, "taken": 18, "account": 18, "misalign": 18, "degrad": 18, "multitud": 18, "retriev": 18, "attach": 18, "buse": 18, "abl": 18, "achiev": 18, "idiosyncrasi": 18, "requir": 18, "identifi": 18, "understand": 18, "dimens": 18, "tree": 18, "zone": 18, "happen": 18, "pick": 18, "best": 18, "depth": 18, "bottom": 18, "top": 18, "repres": 18, "root": 18, "leaf": 18, "behind": 18, "smallest": 18, "distanc": 18, "penalti": 18, "visibl": 18, "space": 18, "union": 18, "children": 18, "practic": 18, "With": 18, "gradual": 18, "increas": 18, "while": 18, "strict": 18, "relax": 18, "easier": 18, "price": 18, "paid": 18, "potenti": 18, "cost": 18, "anoth": 18, "sibl": 18, "descend": 18, "partial": 18, "overlap": [18, 19], "intersect": 18, "decreas": 18, "easi": 18, "As": 18, "ancestor": 18, "arrang": 18, "without": [18, 19], "filter": 18, "insuffici": 18, "score": 18, "remain": 18, "subject": 18, "evolv": 18, "principl": 18, "roughli": 18, "lower": 18, "stricter": 18, "busi": 18, "fewer": 18, "better": 18, "overal": 18, "tightest": 18, "subset": 18, "slice": 18, "mix": 18, "discov": 18, "isolcpu": 18, "notifi": 18, "prevent": 18, "widen": 18, "multi": 18, "know": 18, "kind": 18, "regular": 18, "optan": 18, "hbm": 18, "speed": 18, "found": [18, 19], "some": 18, "initi": [18, 19], "warm": 18, "fragment": 18, "behavior": 18, "suppli": 18, "part": 18, "fallback": [18, 19], "forc": [18, 19], "preferisolatedcpu": 18, "elig": 18, "prefersharedcpu": 18, "glob": 18, "patter": 18, "colocatepod": 18, "try": [18, 19], "colocatenamespac": 18, "check": 18, "could": 18, "benefit": 18, "fulfil": 18, "criteria": 18, "hit": 18, "consist": 18, "five": 18, "slightli": 18, "besteffort": 18, "burstabl": 18, "rule": 18, "among": 18, "fraction": 18, "1000": 18, "milli": 18, "honor": 18, "probabl": 18, "incorrect": 18, "underdeclar": 18, "ordinari": 18, "alon": 18, "usual": 18, "diverg": 18, "resolut": 18, "metadata": 18, "c2": 18, "hw": 18, "prior": 18, "significantli": 18, "sinc": 18, "implicitli": 18, "where": 18, "like": 18, "disregard": 18, "altogeth": 18, "volum": 18, "critic": 18, "manner": 18, "topologyhint": 18, "weight": 18, "extend": 18, "still": 18, "consider": 18, "thorough": 18, "timeout": 18, "unus": 18, "area": 18, "don": 18, "t": 18, "migrat": 18, "becaus": 18, "wa": 18, "begin": 18, "container1": 18, "durat": 18, "60": 18, "again": [18, 19], "altern": 18, "deprec": 18, "drop": 18, "futur": 18, "abov": 18, "grant": 18, "memset": 18, "inaccuraci": 18, "resmgr": 18, "exact": 18, "asid": 18, "section": 18, "my": 18, "mention": 18, "consult": 18, "prefix": [18, 19], "put": 18, "foo": 18, "bar": 18, "whitelist": 18, "path1": 18, "xy": 18, "zy": 18, "pod0c0": 18, "path2": 18, "blacklist": 18, "path3": 18, "pod0c1": 18, "path5": 18, "particular": 18, "express": 18, "far": 18, "awai": 18, "sens": 18, "interpret": 18, "somewhat": 18, "thumb": 18, "farther": 18, "posit": 18, "affinti": 18, "closer": 18, "neg": 18, "further": 18, "toward": 18, "dictionari": 18, "anot": 18, "scope": 18, "ref": 18, "op": 18, "value1": 18, "valuen": 18, "w": 18, "similarli": 18, "strong": 18, "sometim": 18, "reason": 18, "bound": 18, "realli": 18, "compromis": 18, "heavier": 18, "stronger": 18, "propbabl": 18, "omit": 18, "rang": 18, "ident": 18, "qosclass": 18, "id": 18, "uid": 18, "essenti": 18, "boolean": 18, "equal": 18, "item": 18, "notequ": 18, "inequ": 18, "membership": 18, "notin": 18, "negat": 18, "notexist": 18, "alwaystru": 18, "denot": 18, "pattern": 18, "matchesnot": 18, "matchesani": 18, "matchesnon": 18, "c_1": 18, "c_2": 18, "sum": 18, "pairwis": 18, "Then": 18, "asymmetr": 18, "craft": 18, "symmetr": 18, "moreov": 18, "might": 18, "lack": 18, "overcom": 18, "joint": 18, "especi": 18, "join": 18, "sever": 18, "simpl": 18, "full": [18, 19], "format": 18, "colon": 18, "subkei": 18, "equival": 18, "ksep": 18, "vsep": 18, "keylist": 18, "peter": 18, "sheep": 18, "wolf": 18, "container3": 18, "container2": 18, "container4": 18, "thing": 19, "progress": 19, "watch": 19, "themselv": 19, "tt": 19, "veri": 19, "acquir": 19, "agent": 19, "klog": 19, "prepend": 19, "logger_": 19, "capit": 19, "lead": 19, "dash": 19, "logger_skip_head": 19, "skip_head": 19, "logger_debug": 19, "treat": 19, "someth": 19, "until": 19, "origin": 19, "said": 19, "eventu": 19}, "objects": {}, "objtypes": {}, "objnames": {}, "titleterms": {"contribut": 0, "welcom": 1, "nri": [1, 4, 5, 19], "plugin": [1, 3, 4, 5, 13], "document": 1, "content": [1, 3, 13], "introduct": [2, 15, 18], "memori": [3, 4, 14, 18], "qo": [4, 14], "workload": [4, 5], "configur": [4, 5, 6, 16, 18, 19], "class": [4, 5], "unifi": 4, "annot": [4, 18], "exampl": [4, 5, 16, 18], "develop": [4, 5, 10], "": [4, 5, 10], "guid": [4, 5, 10], "prerequisit": [4, 5, 9, 14], "build": [4, 5], "run": [4, 5, 9], "manual": [4, 5, 14], "test": [4, 5, 9, 11, 12], "debug": [4, 5, 16, 19], "deploi": [4, 5], "memtierd": [5, 14], "secur": 5, "dynam": [6, 19], "architectur": 7, "overview": [7, 16, 18], "compon": 7, "node": 7, "agent": 7, "resourc": [7, 13, 19], "manag": 7, "cach": 7, "gener": 7, "polici": [7, 13, 16, 17, 18, 19], "layer": 7, "control": 7, "metric": [7, 16], "collector": 7, "implement": 7, "topologi": [7, 8, 9, 14, 18], "awar": [7, 14, 18], "balloon": [7, 14, 16], "templat": 7, "cpu": [8, 18], "alloc": [8, 18], "base": 8, "priorit": 8, "intel": 8, "speed": 8, "select": 8, "technologi": 8, "sst": 8, "linux": 8, "cpufreq": 8, "end": 9, "usag": [9, 19], "phase": 9, "mode": 9, "from": 9, "scratch": 9, "quick": 9, "rerun": 9, "exist": 9, "virtual": 9, "machin": 9, "custom": 9, "output": 9, "unit": 12, "instal": 14, "helm": 14, "chart": 14, "uninstal": 14, "paramet": [14, 16], "how": 16, "It": 16, "work": 16, "deploy": 16, "assign": 16, "contain": [16, 18], "background": 18, "featur": 18, "activ": 18, "prefer": 18, "share": 18, "exclus": 18, "isol": 18, "implicit": 18, "hardwar": 18, "hint": 18, "topolog": 18, "co": 18, "locat": 18, "pod": 18, "namespac": 18, "cold": 18, "start": 18, "request": 18, "limit": 18, "reserv": 18, "pool": 18, "allow": 18, "deni": 18, "mount": 18, "devic": 18, "path": 18, "via": 18, "affin": 18, "anti": 18, "syntax": 18, "semant": 18, "shorthand": 18, "notat": 18, "setup": 19, "set": 19, "up": 19, "configmap": 19, "log": 19}, "envversion": {"sphinx.domains.c": 2, "sphinx.domains.changeset": 1, "sphinx.domains.citation": 1, "sphinx.domains.cpp": 8, "sphinx.domains.index": 1, "sphinx.domains.javascript": 2, "sphinx.domains.math": 2, "sphinx.domains.python": 3, "sphinx.domains.rst": 2, "sphinx.domains.std": 2, "sphinx": 57}, "alltitles": {"Contributing": [[0, "contributing"]], "Welcome to NRI Plugins documentation": [[1, "welcome-to-nri-plugins-documentation"]], "Contents": [[1, null], [3, null], [13, null]], "Introduction": [[2, "introduction"], [15, "introduction"], [18, "introduction"]], "Memory plugins": [[3, "memory-plugins"]], "Memory QoS NRI plugin": [[4, "memory-qos-nri-plugin"]], "Workload configuration": [[4, "workload-configuration"], [5, "workload-configuration"]], "Plugin configuration": [[4, "plugin-configuration"], [5, "plugin-configuration"]], "Classes": [[4, "classes"], [5, "classes"]], "Unified annotations": [[4, "unified-annotations"]], "Example": [[4, "example"], [5, "example"], [16, "example"]], "Developer\u2019s guide": [[4, "developer-s-guide"], [5, "developer-s-guide"]], "Prerequisites": [[4, "prerequisites"], [5, "prerequisites"], [9, "prerequisites"], [14, "prerequisites"]], "Build": [[4, "build"], [5, "build"]], "Run": [[4, "run"], [5, "run"]], "Manual test": [[4, "manual-test"], [5, "manual-test"]], "Debug": [[4, "debug"], [5, "debug"]], "Deploy": [[4, "deploy"], [5, "deploy"]], "Memtierd NRI plugin": [[5, "memtierd-nri-plugin"]], "Security": [[5, "security"]], "Dynamic Configuration": [[6, "dynamic-configuration"]], "Architecture": [[7, "architecture"]], "Overview": [[7, "overview"], [16, "overview"], [18, "overview"]], "Components": [[7, "components"]], "Node Agent": [[7, "node-agent"]], "Resource Manager": [[7, "resource-manager"]], "Cache": [[7, "cache"]], "Generic Policy Layer": [[7, "generic-policy-layer"]], "Generic Resource Controller Layer": [[7, "generic-resource-controller-layer"]], "Metrics Collector": [[7, "metrics-collector"]], "Policy Implementations": [[7, "policy-implementations"]], "Topology Aware": [[7, "topology-aware"]], "Balloons": [[7, "balloons"], [14, "balloons"]], "Template": [[7, "template"]], "CPU Allocator": [[8, "cpu-allocator"]], "Topology Based Allocation": [[8, "topology-based-allocation"]], "CPU Prioritization": [[8, "cpu-prioritization"]], "Intel Speed Select Technology (SST)": [[8, "intel-speed-select-technology-sst"]], "Linux CPUFreq": [[8, "linux-cpufreq"]], "End-to-End tests": [[9, "end-to-end-tests"]], "Usage": [[9, "usage"]], "Test phases": [[9, "test-phases"]], "Test modes": [[9, "test-modes"]], "Running from scratch and quick rerun in existing virtual machine": [[9, "running-from-scratch-and-quick-rerun-in-existing-virtual-machine"]], "Custom topologies": [[9, "custom-topologies"]], "Test output": [[9, "test-output"]], "Developer\u2019s Guide": [[10, "developer-s-guide"]], "Testing": [[11, "testing"]], "Unit tests": [[12, "unit-tests"]], "Resource Policy Plugins": [[13, "resource-policy-plugins"]], "Installation": [[14, "installation"]], "Installing the Helm Chart": [[14, "installing-the-helm-chart"]], "Uninstalling the Chart": [[14, "uninstalling-the-chart"]], "Helm parameters": [[14, "helm-parameters"]], "Topology-aware": [[14, "topology-aware"]], "Memtierd": [[14, "memtierd"]], "Memory-qos": [[14, "memory-qos"]], "Manual installation": [[14, "manual-installation"]], "Manual uninstallation": [[14, "manual-uninstallation"]], "Balloons Policy": [[16, "balloons-policy"]], "How It Works": [[16, "how-it-works"]], "Deployment": [[16, "deployment"]], "Configuration": [[16, "configuration"]], "Parameters": [[16, "parameters"]], "Assigning a Container to a Balloon": [[16, "assigning-a-container-to-a-balloon"]], "Metrics and Debugging": [[16, "metrics-and-debugging"]], "Policies": [[17, "policies"]], "Topology-Aware Policy": [[18, "topology-aware-policy"]], "Background": [[18, "background"]], "Features": [[18, "features"]], "Activating the Policy": [[18, "activating-the-policy"]], "Configuring the Policy": [[18, "configuring-the-policy"]], "Policy CPU Allocation Preferences": [[18, "policy-cpu-allocation-preferences"]], "Container CPU Allocation Preference Annotations": [[18, "container-cpu-allocation-preference-annotations"]], "Shared, Exclusive, and Isolated CPU Preference": [[18, "shared-exclusive-and-isolated-cpu-preference"]], "Implicit Hardware Topology Hints": [[18, "implicit-hardware-topology-hints"]], "Implicit Topological Co-location for Pods and Namespaces": [[18, "implicit-topological-co-location-for-pods-and-namespaces"]], "Cold Start": [[18, "cold-start"]], "Container memory requests and limits": [[18, "container-memory-requests-and-limits"]], "Reserved pool namespaces": [[18, "reserved-pool-namespaces"]], "Reserved CPU annotations": [[18, "reserved-cpu-annotations"]], "Allowing or denying mount/device paths via annotations": [[18, "allowing-or-denying-mount-device-paths-via-annotations"]], "Container Affinity and Anti-Affinity": [[18, "container-affinity-and-anti-affinity"]], "Affinity Annotation Syntax": [[18, "affinity-annotation-syntax"]], "Affinity Semantics": [[18, "affinity-semantics"]], "Examples": [[18, "examples"]], "Shorthand Notation": [[18, "shorthand-notation"]], "Setup and Usage": [[19, "setup-and-usage"]], "Setting up NRI Resource Policy": [[19, "setting-up-nri-resource-policy"]], "Dynamic configuration with ConfigMaps": [[19, "dynamic-configuration-with-configmaps"]], "Logging and debugging": [[19, "logging-and-debugging"]]}, "indexentries": {}})