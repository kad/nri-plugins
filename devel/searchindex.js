Search.setIndex({"docnames": ["deployment/operator/README", "docs/contributing", "docs/deployment/helm/balloons", "docs/deployment/helm/index", "docs/deployment/helm/memory-qos", "docs/deployment/helm/memtierd", "docs/deployment/helm/sgx-epc", "docs/deployment/helm/template", "docs/deployment/helm/topology-aware", "docs/deployment/index", "docs/deployment/operator/index", "docs/deployment/operator/operator", "docs/index", "docs/introduction", "docs/memory/index", "docs/memory/memory-qos", "docs/memory/memtierd", "docs/memory/sgx-epc", "docs/resource-policy/configuration", "docs/resource-policy/developers-guide/architecture", "docs/resource-policy/developers-guide/cpu-allocator", "docs/resource-policy/developers-guide/e2e-test", "docs/resource-policy/developers-guide/index", "docs/resource-policy/developers-guide/testing", "docs/resource-policy/developers-guide/unit-test", "docs/resource-policy/index", "docs/resource-policy/introduction", "docs/resource-policy/policy/balloons", "docs/resource-policy/policy/index", "docs/resource-policy/policy/template", "docs/resource-policy/policy/topology-aware", "docs/resource-policy/setup"], "filenames": ["deployment/operator/README.md", "docs/contributing.md", "docs/deployment/helm/balloons.md", "docs/deployment/helm/index.md", "docs/deployment/helm/memory-qos.md", "docs/deployment/helm/memtierd.md", "docs/deployment/helm/sgx-epc.md", "docs/deployment/helm/template.md", "docs/deployment/helm/topology-aware.md", "docs/deployment/index.md", "docs/deployment/operator/index.md", "docs/deployment/operator/operator.md", "docs/index.md", "docs/introduction.md", "docs/memory/index.md", "docs/memory/memory-qos.md", "docs/memory/memtierd.md", "docs/memory/sgx-epc.md", "docs/resource-policy/configuration.md", "docs/resource-policy/developers-guide/architecture.md", "docs/resource-policy/developers-guide/cpu-allocator.md", "docs/resource-policy/developers-guide/e2e-test.md", "docs/resource-policy/developers-guide/index.md", "docs/resource-policy/developers-guide/testing.md", "docs/resource-policy/developers-guide/unit-test.md", "docs/resource-policy/index.md", "docs/resource-policy/introduction.md", "docs/resource-policy/policy/balloons.md", "docs/resource-policy/policy/index.md", "docs/resource-policy/policy/template.md", "docs/resource-policy/policy/topology-aware.md", "docs/resource-policy/setup.md"], "titles": ["NRI-Plugins-Operator", "Contributing", "Balloons Policy Plugin", "Helm", "Memory-QoS Plugin", "Memtierd Plugin", "SGX EPC Limit Plugin", "Template Policy Plugin", "Topology-Aware Policy Plugin", "Deployment", "Operator", "NRI-Plugins-Operator", "Welcome to NRI Plugins documentation", "Introduction", "Memory plugins", "Memory QoS NRI plugin", "Memtierd NRI plugin", "SGX EPC Limit Plugin", "Dynamic Configuration", "Architecture", "CPU Allocator", "End-to-End tests", "Developer\u2019s Guide", "Testing", "Unit tests", "Resource Policy Plugins", "Introduction", "Balloons Policy", "Policies", "Template Policy", "Topology-Aware Policy", "Setup and Usage"], "terms": {"The": [0, 2, 3, 4, 5, 6, 7, 8, 11, 13, 16, 17, 18, 19, 20, 21, 26, 27, 28, 29, 30, 31], "i": [0, 7, 8, 11, 13, 15, 16, 19, 20, 21, 26, 27, 29, 30, 31], "an": [0, 2, 4, 5, 6, 7, 8, 11, 15, 16, 19, 21, 27, 30], "ansibl": [0, 11], "base": [0, 11, 13, 19, 27, 30, 31], "creat": [0, 2, 4, 5, 6, 7, 8, 11, 15, 16, 19, 21, 27, 29, 30], "sdk": [0, 11], "manag": [0, 2, 3, 4, 5, 6, 7, 8, 11, 13, 16, 21, 27], "life": [0, 11, 13], "cycl": [0, 11, 13], "deploi": [0, 2, 4, 5, 6, 7, 8, 11, 21, 27, 31], "commun": [0, 11], "maintain": [0, 11], "kubernet": [0, 2, 3, 4, 5, 6, 7, 8, 11, 16, 19, 27, 30, 31], "cluster": [0, 2, 3, 4, 5, 6, 7, 8, 11, 19, 21, 31], "when": [0, 11, 15, 16, 21, 27, 30, 31], "doesn": [0, 11], "t": [0, 11, 30], "do": [0, 11, 15, 16, 19, 27, 30, 31], "anyth": [0, 11, 19], "apart": [0, 11], "from": [0, 3, 11, 15, 16, 18, 19, 27, 30, 31], "watch": [0, 11, 31], "custom": [0, 2, 4, 5, 6, 7, 8, 11, 18, 19, 27, 30], "resourc": [0, 1, 2, 4, 5, 6, 7, 8, 11, 12, 13, 15, 18, 20, 21, 26, 27, 28, 29, 30], "call": [0, 11, 19, 21], "nriplugindeploy": [0, 11], "object": [0, 11, 19, 21, 27], "reconcili": [0, 11], "loop": [0, 11, 19], "kick": [0, 11], "off": [0, 11, 19, 30], "specifi": [0, 2, 4, 5, 6, 7, 8, 11, 16, 27, 30], "build": [0, 11, 30], "imag": [0, 2, 3, 4, 5, 6, 7, 8, 11, 15, 16], "push": [0, 11, 19, 30], "some": [0, 11, 27, 30], "registri": [0, 11], "make": [0, 11, 15, 16, 19, 20, 21, 24, 30], "c": [0, 11], "deploy": [0, 11, 12, 15, 16], "docker": [0, 11, 21], "my": [0, 2, 4, 5, 6, 7, 8, 11, 30], "com": [0, 11, 15, 16], "unstabl": [0, 2, 4, 5, 6, 7, 8, 11], "your": [0, 1, 11], "uninstal": [0, 3, 11], "undeploi": [0, 11], "apivers": [0, 11, 27], "config": [0, 2, 4, 5, 6, 7, 8, 11, 15, 16, 18, 19, 27, 31], "v1alpha1": [0, 11, 27], "kind": [0, 11, 27, 30], "metadata": [0, 11, 17, 27, 30], "name": [0, 2, 4, 5, 6, 7, 8, 11, 15, 16, 18, 19, 21, 27, 30, 31], "sampl": [0, 11, 15, 16, 18], "namespac": [0, 2, 4, 5, 6, 7, 8, 11, 16, 27], "kube": [0, 2, 4, 5, 6, 7, 8, 11, 16, 27, 30], "system": [0, 2, 4, 5, 6, 7, 8, 11, 13, 16, 19, 20, 21, 26, 27, 30], "spec": [0, 11, 27, 30], "pluginnam": [0, 11], "topologi": [0, 3, 9, 11, 25, 27, 28], "awar": [0, 3, 9, 11, 25, 26, 27, 28], "pluginvers": [0, 11], "v0": [0, 11], "2": [0, 3, 11, 15, 16, 19, 21, 27, 30], "3": [0, 2, 4, 5, 6, 7, 8, 11, 27], "state": [0, 11, 19, 27], "present": [0, 2, 4, 5, 6, 7, 8, 11, 27, 30], "valu": [0, 2, 4, 5, 6, 7, 8, 11, 15, 16, 21, 27, 30], "patchruntimeconfig": [0, 2, 4, 5, 6, 7, 8, 11], "true": [0, 2, 4, 5, 6, 7, 8, 11, 16, 27, 30, 31], "toler": [0, 2, 4, 5, 6, 7, 8, 11], "kei": [0, 2, 4, 5, 6, 7, 8, 11, 15, 16, 21, 27, 30], "node": [0, 1, 2, 3, 4, 5, 6, 7, 8, 11, 13, 15, 16, 18, 21, 27, 30], "role": [0, 2, 4, 5, 6, 7, 8, 11], "io": [0, 2, 3, 4, 5, 6, 7, 8, 11, 15, 16, 17, 27, 30], "control": [0, 2, 4, 5, 6, 7, 8, 11, 15, 17, 27, 28, 30, 31], "plane": [0, 2, 4, 5, 6, 7, 8, 11, 19], "exist": [0, 2, 4, 5, 6, 7, 8, 11, 27, 30], "effect": [0, 2, 4, 5, 6, 7, 8, 11, 20, 27, 30, 31], "noschedul": [0, 2, 4, 5, 6, 7, 8, 11], "affin": [0, 2, 4, 5, 6, 8, 11, 27], "nodeaffin": [0, 11], "requiredduringschedulingignoredduringexecut": [0, 11], "nodeselectorterm": [0, 11], "matchexpress": [0, 11, 27], "disk": [0, 11], "In": [0, 11, 15, 19, 21, 27, 30], "ssd": [0, 11], "same": [0, 11, 15, 16, 19, 21, 27, 30, 31], "us": [0, 1, 2, 3, 4, 5, 6, 7, 8, 11, 13, 15, 16, 17, 18, 19, 21, 27, 29, 30, 31], "helm": [0, 2, 4, 5, 6, 7, 8, 9, 11, 12, 31], "chart": [0, 3, 11, 31], "thi": [0, 2, 4, 5, 6, 7, 8, 11, 15, 16, 19, 21, 27, 30, 31], "field": [0, 11, 15], "desir": [0, 11], "current": [0, 9, 11, 19, 20, 21, 27, 28, 30, 31], "accept": [0, 11], "includ": [0, 3, 11, 19, 27], "balloon": [0, 3, 9, 11, 25, 28], "memtierd": [0, 3, 9, 11, 12, 14], "memori": [0, 2, 3, 5, 6, 7, 8, 9, 11, 12, 16, 19, 20, 21], "qo": [0, 3, 9, 11, 12, 14, 30], "sgx": [0, 3, 9, 11, 12, 14], "epc": [0, 3, 9, 11, 12, 14], "list": [0, 11, 15, 16, 27, 30, 31], "allow": [0, 11, 15, 16, 17, 19, 27, 28], "expect": [0, 11], "grow": [0, 11], "new": [0, 1, 7, 11, 19, 27, 29], "ar": [0, 2, 3, 9, 11, 15, 18, 19, 20, 21, 26, 27, 28, 30, 31], "introduc": [0, 11], "immut": [0, 11], "differ": [0, 11, 26, 27, 30], "you": [0, 1, 2, 4, 5, 6, 7, 8, 11, 17, 18, 21, 27, 30, 31], "need": [0, 11, 16, 19, 27, 30, 31], "re": [0, 11], "one": [0, 11, 18, 19, 20, 21, 27, 30], "version": [0, 2, 3, 4, 5, 6, 7, 8, 11, 30], "If": [0, 11, 15, 16, 19, 20, 21, 27, 30], "indic": [0, 11, 21, 30], "default": [0, 2, 4, 5, 6, 7, 8, 11, 15, 16, 18, 21, 27, 30, 31], "latest": [0, 11, 15, 16], "mutabl": [0, 11], "updat": [0, 11, 19, 31], "befor": [0, 11], "determin": [0, 11, 19, 30], "whether": [0, 11, 18, 26, 30], "absent": [0, 11], "user": [0, 2, 4, 5, 6, 7, 8, 11, 16, 19, 27, 28, 30], "provid": [0, 2, 3, 4, 5, 6, 7, 8, 11, 19, 28, 30], "manipul": [0, 11], "requir": [0, 11, 30], "recreat": [0, 11], "pass": [0, 11, 19, 21], "statu": [0, 11, 15, 16, 21], "track": [0, 11, 16, 19], "basic": [0, 11, 19, 30], "messag": [0, 11], "case": [0, 11, 21, 27, 30], "encount": [0, 11], "issu": [0, 1, 11], "while": [0, 3, 11, 30], "reconcil": [0, 11], "pleas": 1, "github": [1, 2, 4, 5, 6, 7, 8, 12, 15, 16], "infrastructur": 1, "nri": [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 13, 14, 17, 18, 19, 20, 21, 25, 26, 27, 30], "plugin": [1, 3, 9, 10, 13, 18, 19, 26, 31], "pull": [1, 2, 4, 5, 6, 7, 8, 30], "request": [1, 6, 19, 20, 26, 27], "code": 1, "bug": 1, "fix": [1, 27], "want": [1, 21, 31], "discuss": 1, "idea": 1, "term": [1, 20], "open": 1, "report": [1, 21], "featur": [1, 2, 4, 5, 6, 7, 8, 20], "ani": [1, 7, 16, 18, 19, 27, 29, 30, 31], "other": [1, 15, 16, 18, 19, 20, 27, 30], "topic": 1, "relat": [1, 19], "For": [1, 2, 4, 5, 6, 7, 8, 13, 15, 19, 20, 21, 30, 31], "actual": [1, 7, 15], "interfac": [1, 2, 4, 5, 6, 7, 8, 13, 19, 27], "api": [1, 19, 26], "see": [1, 2, 7, 8, 15, 16, 18, 20, 27], "repositori": [1, 12], "implement": [2, 7, 26, 27, 29, 30], "workload": [2, 5, 14, 19, 20, 27, 28, 30], "placement": [2, 27, 30], "disjoint": [2, 27, 30], "cpu": [2, 4, 5, 6, 7, 8, 21, 22, 25], "pool": [2, 27], "1": [2, 3, 4, 5, 6, 7, 8, 15, 16, 21, 27, 30], "24": [2, 4, 5, 6, 7, 8], "0": [2, 4, 5, 6, 7, 8, 15, 21, 27, 30], "contain": [2, 3, 4, 5, 6, 7, 8, 13, 15, 16, 17, 18, 19, 21, 26, 31], "runtim": [2, 4, 5, 6, 7, 8, 19, 21, 26, 27, 31], "containerd": [2, 3, 4, 5, 6, 7, 8, 15, 16, 21, 26, 31], "At": [2, 4, 5, 6, 7, 8], "least": [2, 4, 5, 6, 7, 8, 27], "7": [2, 3, 4, 5, 6, 7, 8, 15, 16], "releas": [2, 4, 5, 6, 7, 8, 19, 30], "enabl": [2, 4, 5, 6, 7, 8, 15, 16, 20, 27, 30], "follow": [2, 4, 5, 6, 7, 8, 15, 16, 17, 19, 27, 30], "detail": [2, 4, 5, 6, 7, 8, 19, 20, 26, 27, 30], "instruct": [2, 4, 5, 6, 7, 8], "can": [2, 3, 4, 5, 6, 7, 8, 13, 17, 18, 19, 21, 27, 29, 30, 31], "dure": [2, 4, 5, 6, 7, 8, 27, 30], "simpli": [2, 4, 5, 6, 7, 8, 19], "set": [2, 4, 5, 6, 7, 8, 15, 16, 18, 19, 25, 26, 27, 30], "paramet": [2, 4, 5, 6, 7, 8, 15, 20], "instanc": [2, 4, 5, 6, 7, 8, 15, 19, 27, 30, 31], "init": [2, 4, 5, 6, 7, 8], "turn": [2, 4, 5, 6, 7, 8, 31], "onli": [2, 3, 4, 5, 6, 7, 8, 16, 20, 21, 27, 30], "after": [2, 4, 5, 6, 7, 8, 27, 30], "proce": [2, 4, 5, 6, 7, 8], "cri": [2, 4, 5, 6, 7, 8, 26, 30, 31], "o": [2, 3, 4, 5, 6, 7, 8, 16, 26, 30, 31], "v1": [2, 4, 5, 6, 7, 8, 15, 16], "26": [2, 4, 5, 6, 7, 8], "path": [2, 4, 5, 6, 7, 8, 16], "repo": [2, 4, 5, 6, 7, 8], "add": [2, 4, 5, 6, 7, 8, 15, 19, 27], "http": [2, 4, 5, 6, 7, 8, 27], "command": [2, 4, 5, 6, 7, 8, 16, 21, 27, 31], "abov": [2, 4, 5, 6, 7, 8, 30], "within": [2, 4, 5, 6, 7, 8, 19, 27, 30], "To": [2, 4, 5, 6, 7, 8, 16, 30], "avail": [2, 3, 4, 5, 6, 7, 8, 13, 18, 21, 26, 27, 30, 31], "describ": [2, 4, 5, 6, 7, 8], "below": [2, 4, 5, 6, 7, 8, 27, 30], "have": [2, 4, 5, 6, 7, 8, 19, 20, 21, 27, 30, 31], "two": [2, 4, 5, 6, 7, 8, 15, 18, 20, 21, 27, 28, 30], "flag": [2, 4, 5, 6, 7, 8, 20], "yaml": [2, 4, 5, 6, 7, 8, 15, 16, 30], "file": [2, 4, 5, 6, 7, 8, 15, 16, 19, 31], "f": [2, 4, 5, 6, 7, 8, 15, 16], "exampl": [2, 4, 5, 6, 7, 8, 13, 20, 21], "cat": [2, 4, 5, 6, 7, 8], "eof": [2, 4, 5, 6, 7, 8], "mypath": [2, 4, 5, 6, 7, 8], "oper": [2, 4, 5, 6, 7, 8, 9, 12, 30], "run": [2, 4, 5, 6, 7, 8, 19, 24, 26, 27, 30, 31], "delet": [2, 4, 5, 6, 7, 8, 18, 19, 21], "tabl": [2, 4, 5, 6, 7, 8], "overview": [2, 4, 5, 6, 7, 8], "own": [2, 4, 5, 6, 7, 8], "along": [2, 4, 5, 6, 7, 8, 30], "descript": [2, 4, 5, 6, 7, 8, 27], "ghcr": [2, 4, 5, 6, 7, 8], "tag": [2, 4, 5, 6, 7, 8, 30], "pullpolici": [2, 4, 5, 6, 7, 8], "alwai": [2, 4, 5, 6, 7, 8, 18, 27, 30], "500m": [2, 7, 8], "pod": [2, 4, 5, 6, 7, 8, 13, 15, 16, 17, 19, 27], "512mi": [2, 7, 8], "qouta": [2, 4, 5, 6, 7, 8], "hostport": [2, 7, 8], "8891": [2, 7, 8, 27], "metric": [2, 7, 8], "port": [2, 7, 8], "expos": [2, 7, 8, 30], "host": [2, 3, 5, 7, 8, 16], "data": [2, 7, 8, 15, 16, 19, 30], "configgrouplabel": [2, 7, 8], "group": [2, 7, 8, 15, 18, 21, 30], "label": [2, 4, 5, 6, 7, 8, 18, 19, 30], "fals": [2, 4, 5, 6, 7, 8, 15, 16, 27, 30], "pluginindex": [2, 4, 5, 6, 7, 8], "90": [2, 7, 8], "index": [2, 4, 5, 6, 7, 8], "regist": [2, 4, 5, 6, 7, 8], "initimag": [2, 4, 5, 6, 7, 8], "taint": [2, 4, 5, 6, 7, 8, 19], "nodeselector": [2, 4, 5, 6, 8], "selector": [2, 4, 5, 6, 8], "podpriorityclassnodecrit": [2, 4, 5, 6, 7, 8], "mark": [2, 4, 5, 6, 7, 8, 20, 30], "critic": [2, 4, 5, 6, 7, 8, 30], "all": [3, 15, 16, 17, 19, 20, 21, 27, 30], "found": [3, 30], "artifacthub": 3, "note": [3, 30, 31], "instal": [3, 9, 10, 15, 16, 21], "ha": [3, 15, 16, 19, 20, 27, 30, 31], "been": [3, 16, 20, 27], "successfulli": 3, "verifi": 3, "both": [3, 16, 19, 21, 30], "local": [3, 16, 27, 30, 31], "major": 3, "cloud": 3, "aw": 3, "ek": 3, "28": 3, "x": 3, "amazon": 3, "linux": [3, 15, 21], "ubuntu": 3, "20": [3, 16], "04": 3, "googl": 3, "gke": 3, "optim": [3, 19, 20, 30], "co": [3, 27], "22": 3, "azur": 3, "ak": 3, "wa": [3, 30], "across": [3, 19, 27], "three": [3, 20, 30], "csp": 3, "environ": [3, 21, 31], "": [3, 12, 14, 19, 21, 25, 27, 30], "worth": 3, "limit": [3, 9, 12, 14, 15, 27], "wide": 3, "recogn": 3, "distribut": [3, 19, 21], "should": [3, 16, 19, 27, 30], "suitabl": 3, "polici": [3, 4, 5, 6, 9, 12, 13, 16, 18, 20, 21, 26], "prerequisit": 3, "configur": [3, 12, 14, 19, 20, 21, 25, 26, 28], "option": [3, 16, 27, 30, 31], "templat": [3, 9, 16, 25, 28], "method": [4, 9, 15], "cgroup": [4, 6, 15, 16, 17], "v2": [4, 6, 15, 16, 17], "class": [4, 20, 27, 30], "direct": [4, 15, 19], "annot": [4, 6, 14, 16, 19, 27], "10m": 4, "100mi": [4, 5, 6], "40": [4, 6, 15, 16], "250m": 5, "outputdir": 5, "empti": [5, 30], "string": [5, 15, 16, 27, 30], "directori": [5, 16, 21], "output": [5, 16], "45": 5, "encrypt": [6, 17], "page": [6, 16, 17], "cach": [6, 17], "usag": [6, 12, 15, 17, 25, 27, 30], "yet": 6, "merg": 6, "misc": [6, 17], "25m": 6, "wirefram": [7, 29], "without": [7, 27, 29, 30, 31], "logic": [7, 27, 29, 30], "It": [7, 19, 26, 29], "serv": [7, 29], "appli": [8, 21, 26, 30], "hardwar": [8, 20, 26, 27], "alloc": [8, 13, 15, 16, 19, 22, 25, 26, 27, 28, 29], "support": [9, 20, 21, 30, 31], "introduct": [10, 12, 25], "crd": 10, "setup": [12, 21, 25, 27, 30], "dynam": [12, 19, 25, 27, 30], "develop": [12, 14, 19, 25], "guid": [12, 14, 25], "contribut": 12, "project": 12, "collect": [13, 19], "variou": [13, 19, 30], "aspect": [13, 19], "modifi": [13, 15, 16, 19], "depend": [13, 18, 19, 26, 30], "secur": 14, "There": [15, 18, 21, 26, 27, 30], "calcul": [15, 30], "wai": [15, 19, 28, 30], "belong": [15, 16, 18, 27, 30], "specif": [15, 16, 17, 18, 19, 20, 27, 30, 31], "defin": [15, 16, 19, 21, 27, 30], "silver": 15, "overrid": [15, 16, 27], "c0": [15, 16, 17], "bronz": 15, "remov": [15, 18, 19, 27], "c1": [15, 16, 30], "given": [15, 27, 30], "affect": [15, 16, 19, 27, 30], "swap": [15, 16], "max": [15, 16, 27], "high": [15, 19, 20, 27, 30], "oom": [15, 30], "never": [15, 30], "noswap": 15, "process": [15, 16, 19], "get": [15, 19, 21, 27, 30, 31], "kill": [15, 27], "whole": [15, 30], "map": [15, 16, 20], "match": [15, 16, 27, 30], "swaplimitratio": 15, "minimum": [15, 27], "ratio": 15, "consumpt": 15, "reach": 15, "adjust": [15, 19], "watermark": 15, "unifiedannot": 15, "oci": 15, "whose": [15, 27], "thei": [15, 27, 30], "impli": [15, 30], "5": [15, 16, 19, 30], "belog": 15, "half": 15, "its": [15, 18, 19, 27, 30], "next": [15, 27], "caus": [15, 19, 27, 30], "kernel": [15, 27, 30], "out": [15, 16, 27, 30], "correspond": [15, 19, 27, 30, 31], "amount": [15, 16, 30], "word": [15, 30], "close": [15, 20, 27, 30], "most": [15, 19, 27, 30], "store": [15, 16, 30], "ram": [15, 21], "keep": [15, 19, 27], "up": [15, 19, 25, 27, 30], "80": 15, "directli": [15, 19], "etc": [15, 16], "toml": [15, 16], "disabl": [15, 16, 20, 31], "disable_connect": [15, 16], "plugin_config_path": [15, 16], "conf": [15, 16], "d": [15, 16], "plugin_path": [15, 16], "opt": [15, 16, 30], "plugin_registration_timeout": [15, 16], "plugin_request_timeout": [15, 16], "socket_path": [15, 16], "var": [15, 16, 21], "sock": [15, 16], "cd": [15, 16, 21], "cmd": [15, 16], "go": [15, 16, 19, 21], "idx": [15, 16], "vv": [15, 16], "kubectl": [15, 16], "e2": [15, 16, 21], "dd": [15, 16], "each": [15, 16, 19, 20, 21, 26, 27, 30, 31], "pid": [15, 16], "pidof": [15, 16], "grep": [15, 16], "vmswap": [15, 16], "proc": [15, 16], "done": [15, 16, 30], "delv": [15, 16], "dlv": [15, 16], "exec": [15, 16], "break": [15, 16], "createcontain": [15, 16], "continu": [15, 16], "import": [15, 16], "rm": [15, 16, 20], "rf": [15, 16], "clean": 15, "image_vers": [15, 16], "devel": [15, 16], "ctr": [15, 16], "n": [15, 16], "k8": [15, 16, 30], "tar": [15, 16], "attribut": [16, 27], "launch": 16, "idl": [16, 27, 30], "work": [16, 31], "size": [16, 21, 27], "associ": [16, 19, 20], "allowswap": 16, "disallow": 16, "what": [16, 30], "written": 16, "memtierdconfig": 16, "which": [16, 19, 26, 27, 30], "variabl": [16, 21, 31], "replac": 16, "cgroup2_abs_path": 16, "absolut": 16, "ag": 16, "intervalm": 16, "10000": 16, "pidwatch": 16, "swapoutm": 16, "tracker": 16, "idlepag": 16, "pagesinregion": 16, "512": 16, "maxcountperregion": 16, "scanintervalm": 16, "mover": 16, "bandwidth": [16, 30], "50": 16, "sure": [16, 19], "decid": [16, 19, 27, 30], "mean": [16, 27, 30], "find": 16, "access": [16, 19, 27, 30], "10": [16, 30], "second": [16, 27, 30], "m": 16, "interv": [16, 27], "more": [16, 18, 20, 21, 27, 28, 30], "than": [16, 19, 27, 30], "mb": 16, "refer": [16, 30], "document": [16, 18, 20, 27], "gobin": 16, "usr": 16, "bin": 16, "intel": [16, 30], "v": 16, "even": [16, 27], "verbos": [16, 27], "under": [16, 21, 30], "tmp": 16, "variant": 16, "give": [16, 21, 30], "log": [16, 19, 21, 25, 27], "privileg": 16, "order": [16, 20, 21, 27, 28], "activ": [16, 19, 20, 30], "move": [16, 30], "therefor": [16, 21, 30], "must": [16, 21], "configmap": 16, "execut": [16, 21], "mode": [16, 19], "over": [17, 18, 27, 30], "everi": [17, 27], "just": [17, 19, 30], "notat": 17, "32768": 17, "altern": [17, 30], "8192": 17, "16384": 17, "daemon": 18, "monitor": 18, "primari": 18, "secondari": 18, "take": [18, 19, 20, 30], "preced": [18, 30], "node_nam": 18, "group_nam": 18, "assign": [18, 19, 29, 30], "inform": 18, "later": [19, 27], "rp": 19, "plug": 19, "mai": [19, 20, 27, 30], "alter": [19, 26, 30], "whenev": [19, 27, 30], "receiv": 19, "result": [19, 27, 30], "chang": [19, 21, 27, 30, 31], "creation": [19, 30], "built": [19, 20, 27], "algorithm": [19, 30], "decis": [19, 27], "about": [19, 30], "how": [19, 26, 30], "intern": 19, "abstract": 19, "record": 19, "mani": [19, 27], "These": [19, 27, 30, 31], "although": [19, 30], "static": [19, 27], "prefer": [19, 20, 27], "itself": 19, "interact": 19, "through": [19, 27], "perform": [19, 20, 26, 30], "behalf": 19, "function": [19, 21, 30], "extern": 19, "capac": [19, 30], "grpc": 19, "server": [19, 27, 30], "act": [19, 30], "client": 19, "low": [19, 20, 27, 30], "level": [19, 27], "conveni": 19, "plumb": 19, "addition": [19, 30, 31], "stock": 19, "come": 19, "scheme": 19, "event": 19, "pipelin": 19, "addit": 19, "typic": [19, 30], "flow": 19, "necessari": 19, "sub": [19, 30], "phase": 19, "serial": 19, "being": [19, 27, 30], "point": [19, 29], "time": [19, 30], "A": [19, 27, 30], "doe": [19, 20, 27, 30], "let": 19, "bypass": 19, "hand": [19, 27, 30], "relai": 19, "respons": 19, "back": 19, "b": 19, "intercept": 19, "lock": 19, "look": [19, 27], "consequ": 19, "proxi": 19, "step": 19, "6": 19, "otherwis": [19, 21, 27, 30], "invok": 19, "post": 19, "pend": 19, "domain": 19, "clear": 19, "marker": 19, "send": 19, "type": [19, 20, 27, 30], "engag": 19, "handler": 19, "share": 19, "storag": 19, "locat": 19, "known": 19, "well": [19, 30], "save": [19, 21, 27], "perman": 19, "filesystem": 19, "restor": 19, "restart": 19, "queri": 19, "mechan": 19, "accord": [19, 27, 30], "abil": 19, "enforc": 19, "first": [19, 21, 27, 30], "accordingli": 19, "howev": [19, 30], "instead": [19, 30], "assum": [19, 31], "caller": 19, "proper": 19, "protect": 19, "place": [19, 27, 30], "against": [19, 30], "concurr": 19, "read": [19, 27], "write": 19, "unsolicit": 19, "iow": [19, 27, 30], "handl": [19, 30], "backend": 19, "inject": 19, "callback": 19, "argument": 19, "properli": [19, 30], "rest": 19, "care": [19, 30], "dispatch": 19, "gather": 19, "period": [19, 30], "evalu": [19, 27, 30], "attempt": 19, "rebalanc": 19, "realloc": 19, "deem": 19, "possibl": [19, 20, 30], "capabl": 19, "multipl": [19, 30], "tier": [19, 30], "dram": [19, 30], "pmem": [19, 30], "combin": [19, 30], "fine": 19, "grain": 19, "comput": [19, 30], "hook": 19, "fill": [19, 27], "edit": 19, "copi": [19, 21, 30], "separ": [20, 27, 30], "compon": 20, "help": [20, 21, 27], "educ": 20, "core": [20, 21, 27, 30], "util": 20, "tri": 20, "aim": 20, "pack": [20, 27], "minim": 20, "latenc": [20, 30], "between": [20, 27, 30], "also": [20, 30], "automat": [20, 27, 30], "detect": [20, 30], "prioriti": [20, 30], "intel_pst": 20, "scale": 20, "driver": 20, "subsystem": 20, "divid": [20, 30], "e": 20, "normal": [20, 21, 27, 30], "choos": [20, 27], "certain": [20, 21, 30], "preserv": [20, 27, 30], "profil": 20, "pp": 20, "frequenc": [20, 27], "bf": 20, "turbo": [20, 27], "tf": 20, "power": [20, 27], "cp": 20, "parameter": 20, "examin": 20, "servic": 20, "highest": [20, 27], "clo": 20, "lowest": 20, "middl": 20, "inact": 20, "higher": 20, "guarante": [20, 30], "epp": 20, "energi": 20, "rel": 20, "correspondingli": 20, "vagrant": 21, "run_test": 21, "sh": 21, "suit": 21, "select": [21, 27, 30], "testnn": 21, "definit": [21, 27, 30], "script": 21, "unless": [21, 27, 30], "alreadi": [21, 27, 30, 31], "singl": [21, 27, 30], "daemonset": 21, "bash": 21, "helper": 21, "observ": 21, "softwar": 21, "tear": 21, "down": 21, "final": [21, 30], "stop": 21, "fast": 21, "verdict": 21, "fail": 21, "exit": 21, "zero": [21, 28], "vm_name": 21, "construct": 21, "vm": 21, "destroi": [21, 27], "numa": [21, 27, 30], "ignor": 21, "json": 21, "arrai": 21, "mem": 21, "0g": 21, "nvmem": 21, "non": [21, 30], "volatil": 21, "number": [21, 27, 30], "thread": [21, 27], "die": [21, 27, 30], "di": [21, 27, 30], "packag": [21, 27], "4": [21, 27, 30], "per": [21, 30], "4g": 21, "my2x4": 21, "32": 21, "total": 21, "socket": [21, 27, 30], "And": 21, "16g": 21, "nvram": 21, "mynvram": 21, "outdir": 21, "standard": 21, "n4c16": 21, "gener": [21, 30], "fedora37": 21, "would": [21, 27, 30], "four": 21, "16": 21, "fedora": 21, "37": 21, "timestamp": 21, "architectur": [22, 25, 30], "test": [22, 25], "unit": 23, "end": [23, 30], "debug": 25, "connect": 26, "via": 26, "main": [26, 30], "purpos": [26, 30], "goal": 26, "mind": 26, "strategi": 26, "extra": [26, 27, 30, 31], "action": 26, "inflat": 27, "deflat": 27, "ad": [27, 30], "min": 27, "uncor": 27, "exactli": 27, "lifetim": 27, "opposit": 27, "enough": [27, 30], "fit": [27, 30], "reconfigur": [27, 31], "balloonspolici": 27, "reservedresourc": [27, 30], "cpuset": 27, "special": [27, 30], "reserv": 27, "By": 27, "48": 27, "cpu0": 27, "cpu48": 27, "2000m": 27, "mincpu": 27, "explicitli": 27, "maxcpu": 27, "pincpu": [27, 30], "cannot": 27, "pinmemori": [27, 30], "closest": [27, 30], "warn": 27, "due": [27, 30], "error": 27, "situat": [27, 30], "consid": [27, 30], "switch": 27, "idlecpuclass": 27, "those": [27, 30], "reservedpoolnamespac": [27, 30], "wildcard": [27, 30], "allocatortopologybalanc": 27, "free": [27, 30], "spread": 27, "reduc": 27, "interfer": 27, "fulli": [27, 30], "load": 27, "tightli": 27, "larg": [27, 30], "portion": 27, "enter": 27, "deep": 27, "preferspreadonphysicalcor": 27, "possibli": 27, "hyperthread": 27, "physic": 27, "prevent": [27, 30], "interf": 27, "themselv": [27, 31], "compet": 27, "On": [27, 30], "here": [27, 31], "overridden": [27, 31], "balloontyp": 27, "signific": 27, "pre": 27, "start": [27, 29], "minballoon": 27, "allocatorprior": 27, "lower": [27, 30], "theirs": 27, "them": [27, 30], "assignd": 27, "criteria": [27, 30], "express": [27, 30], "mach": 27, "syntax": 27, "semant": 27, "scope": [27, 30], "maxballoon": 27, "maximum": [27, 30], "larger": [27, 30], "unlimit": 27, "less": 27, "cpuclass": 27, "properti": [27, 30], "preferclosetodevic": 27, "devic": 27, "preferspreadingpod": 27, "preferpernamespaceballoon": 27, "preferr": 27, "prefernewballoon": 27, "exclus": 27, "long": [27, 30], "ones": [27, 30], "shareidlecpusinsam": 27, "reshar": 27, "common": [27, 30], "anywher": 27, "fulfil": [27, 30], "anti": 27, "awai": [27, 30], "sy": 27, "net": 27, "eth0": 27, "block": 27, "sda": 27, "none": 27, "resiz": 27, "minfreq": 27, "khz": 27, "maxfreq": 27, "uncoreminfreq": 27, "zone": [27, 30], "uncoremaxfreq": 27, "instrument": 27, "httpendpoint": 27, "address": 27, "listen": 27, "prometheusexport": 27, "readabl": 27, "reportperiod": 27, "aggreg": 27, "localhost": 27, "1000m": 27, "lowpow": 27, "quad": 27, "800000": 27, "3600000": 27, "3000000": 27, "2000000": 27, "2400000": 27, "bt": 27, "container_nam": [27, 30], "last": 27, "among": [27, 30], "restrict": [27, 30], "touch": [27, 30], "export": 27, "global": [27, 30, 31], "line": [27, 31], "curl": 27, "silent": 27, "logger": 27, "nearli": 28, "evenli": 28, "avoid": [28, 30], "noisi": 28, "neighbor": 28, "problem": 28, "real": 29, "grade": 30, "peripher": 30, "form": 30, "rather": 30, "complex": 30, "network": 30, "togeth": 30, "bu": 30, "hierarchi": 30, "interconnect": 30, "vari": 30, "greatli": 30, "effici": 30, "transfer": 30, "align": 30, "inher": 30, "taken": [30, 31], "account": 30, "misalign": 30, "degrad": 30, "multitud": 30, "retriev": 30, "attach": 30, "buse": 30, "abl": 30, "achiev": 30, "idiosyncrasi": 30, "identifi": 30, "understand": 30, "dimens": 30, "tree": 30, "happen": 30, "pick": 30, "best": 30, "depth": 30, "bottom": 30, "top": 30, "repres": 30, "root": 30, "leaf": 30, "behind": 30, "smallest": 30, "distanc": 30, "penalti": 30, "machin": 30, "visibl": 30, "space": 30, "union": 30, "children": 30, "so": 30, "practic": 30, "With": 30, "gradual": 30, "increas": 30, "strict": 30, "relax": 30, "easier": 30, "price": 30, "paid": 30, "potenti": 30, "cost": 30, "anoth": 30, "sibl": 30, "descend": 30, "partial": 30, "overlap": 30, "intersect": 30, "decreas": 30, "easi": 30, "As": 30, "ancestor": 30, "arrang": 30, "filter": 30, "insuffici": 30, "score": 30, "remain": 30, "subject": 30, "evolv": 30, "principl": 30, "roughli": 30, "stricter": 30, "busi": 30, "fewer": 30, "better": 30, "overal": 30, "tightest": 30, "subset": 30, "slice": 30, "mix": 30, "discov": 30, "isolcpu": 30, "notifi": 30, "widen": 30, "multi": 30, "know": 30, "regular": 30, "optan": 30, "hbm": 30, "speed": 30, "initi": 30, "warm": 30, "behavior": 30, "suppli": [30, 31], "part": 30, "preferisolatedcpu": 30, "elig": 30, "prefersharedcpu": 30, "glob": 30, "patter": 30, "colocatepod": 30, "try": [30, 31], "colocatenamespac": 30, "check": 30, "could": 30, "benefit": 30, "reflect": 30, "hit": 30, "consist": 30, "five": 30, "slightli": 30, "besteffort": 30, "burstabl": 30, "rule": 30, "either": [30, 31], "fraction": 30, "1000": 30, "milli": 30, "honor": 30, "probabl": 30, "incorrect": 30, "underdeclar": 30, "ordinari": 30, "alon": 30, "usual": 30, "diverg": 30, "resolut": 30, "c2": 30, "hw": 30, "prior": 30, "significantli": 30, "sinc": 30, "implicitli": 30, "where": 30, "like": 30, "disregard": 30, "altogeth": 30, "volum": 30, "manner": 30, "topologyhint": 30, "weight": 30, "extend": 30, "still": 30, "consider": 30, "thorough": 30, "timeout": 30, "unus": 30, "area": 30, "don": 30, "migrat": 30, "becaus": 30, "begin": 30, "container1": 30, "durat": 30, "60": 30, "again": 30, "deprec": 30, "drop": 30, "futur": 30, "grant": 30, "memset": 30, "inaccuraci": 30, "resmgr": 30, "exact": 30, "asid": 30, "section": 30, "mention": 30, "consult": 30, "prefix": [30, 31], "put": 30, "foo": 30, "bar": 30, "whitelist": 30, "path1": 30, "xy": 30, "zy": 30, "pod0c0": 30, "path2": 30, "blacklist": 30, "path3": 30, "pod0c1": 30, "path5": 30, "particular": 30, "far": 30, "sens": 30, "interpret": 30, "somewhat": 30, "thumb": 30, "farther": 30, "posit": 30, "affinti": 30, "closer": 30, "neg": 30, "further": 30, "toward": 30, "dictionari": 30, "anot": 30, "ref": 30, "op": 30, "value1": 30, "valuen": 30, "w": 30, "similarli": 30, "strong": 30, "sometim": 30, "reason": 30, "bound": 30, "realli": 30, "compromis": 30, "heavier": 30, "stronger": 30, "propbabl": 30, "omit": 30, "rang": 30, "ident": 30, "qosclass": 30, "id": 30, "uid": 30, "essenti": 30, "boolean": 30, "equal": 30, "item": 30, "notequ": 30, "inequ": 30, "membership": 30, "notin": 30, "negat": 30, "notexist": 30, "alwaystru": 30, "denot": 30, "pattern": 30, "matchesnot": 30, "matchesani": 30, "matchesnon": 30, "c_1": 30, "c_2": 30, "sum": 30, "pairwis": 30, "Then": 30, "asymmetr": 30, "craft": 30, "symmetr": 30, "moreov": 30, "might": 30, "lack": 30, "overcom": 30, "joint": 30, "especi": 30, "join": 30, "sever": 30, "simpl": 30, "full": [30, 31], "format": 30, "colon": 30, "subkei": 30, "equival": 30, "ksep": 30, "vsep": 30, "keylist": 30, "peter": 30, "sheep": 30, "wolf": 30, "container3": 30, "container2": 30, "container4": 30, "thing": 31, "progress": 31, "klog": 31, "prepend": 31, "logger_": 31, "capit": 31, "lead": 31, "dash": 31, "logger_skip_head": 31, "skip_head": 31, "logger_debug": 31, "onc": 31, "suppress": 31}, "objects": {}, "objtypes": {}, "objnames": {}, "titleterms": {"nri": [0, 11, 12, 15, 16, 31], "plugin": [0, 2, 4, 5, 6, 7, 8, 11, 12, 14, 15, 16, 17, 25], "oper": [0, 10, 11], "introduct": [0, 11, 13, 26, 30], "instal": [0, 2, 4, 5, 6, 7, 8, 11], "crd": [0, 11], "contribut": 1, "balloon": [2, 19, 27], "polici": [2, 7, 8, 19, 25, 27, 28, 29, 30, 31], "prerequisit": [2, 4, 5, 6, 7, 8, 15, 16, 21], "chart": [2, 4, 5, 6, 7, 8], "uninstal": [2, 4, 5, 6, 7, 8], "configur": [2, 4, 5, 6, 7, 8, 15, 16, 18, 27, 30, 31], "option": [2, 4, 5, 6, 7, 8], "helm": 3, "content": [3, 9, 10, 12, 14, 25], "memori": [4, 14, 15, 27, 30], "qo": [4, 15], "memtierd": [5, 16], "sgx": [6, 17], "epc": [6, 17], "limit": [6, 17, 30], "templat": [7, 19, 29], "topologi": [8, 19, 20, 21, 30], "awar": [8, 19, 30], "deploy": [9, 27], "welcom": 12, "document": 12, "workload": [15, 16], "class": [15, 16], "unifi": 15, "annot": [15, 17, 30], "exampl": [15, 16, 27, 30], "develop": [15, 16, 22], "": [15, 16, 22], "guid": [15, 16, 22], "build": [15, 16], "run": [15, 16, 21], "manual": [15, 16], "test": [15, 16, 21, 23, 24], "debug": [15, 16, 27, 31], "deploi": [15, 16], "secur": 16, "dynam": [18, 31], "architectur": 19, "overview": [19, 27, 30], "compon": 19, "node": 19, "agent": 19, "resourc": [19, 25, 31], "manag": 19, "cach": 19, "gener": 19, "layer": 19, "control": 19, "metric": [19, 27], "collector": 19, "implement": 19, "cpu": [20, 27, 30], "alloc": [20, 30], "base": 20, "priorit": 20, "intel": 20, "speed": 20, "select": 20, "technologi": 20, "sst": 20, "linux": 20, "cpufreq": 20, "end": 21, "usag": [21, 31], "phase": 21, "mode": 21, "from": 21, "scratch": 21, "quick": 21, "rerun": 21, "exist": 21, "virtual": 21, "machin": 21, "custom": [21, 31], "output": 21, "unit": 24, "how": 27, "It": 27, "work": 27, "paramet": 27, "assign": 27, "contain": [27, 30], "disabl": [27, 30], "pin": [27, 30], "background": 30, "featur": 30, "prefer": 30, "share": 30, "exclus": 30, "isol": 30, "implicit": 30, "hardwar": 30, "hint": 30, "topolog": 30, "co": 30, "locat": 30, "pod": 30, "namespac": 30, "cold": 30, "start": 30, "request": 30, "reserv": 30, "pool": 30, "allow": 30, "deni": 30, "mount": 30, "devic": 30, "path": 30, "via": 30, "affin": 30, "anti": 30, "syntax": 30, "semant": 30, "shorthand": 30, "notat": 30, "setup": 31, "set": 31, "up": 31, "log": 31}, "envversion": {"sphinx.domains.c": 2, "sphinx.domains.changeset": 1, "sphinx.domains.citation": 1, "sphinx.domains.cpp": 8, "sphinx.domains.index": 1, "sphinx.domains.javascript": 2, "sphinx.domains.math": 2, "sphinx.domains.python": 3, "sphinx.domains.rst": 2, "sphinx.domains.std": 2, "sphinx": 57}, "alltitles": {"NRI-Plugins-Operator": [[0, "nri-plugins-operator"], [11, "nri-plugins-operator"]], "Introduction": [[0, "introduction"], [11, "introduction"], [13, "introduction"], [26, "introduction"], [30, "introduction"]], "Installation": [[0, "installation"], [11, "installation"]], "Operator CRD": [[0, "operator-crd"], [11, "operator-crd"]], "Contributing": [[1, "contributing"]], "Balloons Policy Plugin": [[2, "balloons-policy-plugin"]], "Prerequisites": [[2, "prerequisites"], [4, "prerequisites"], [5, "prerequisites"], [6, "prerequisites"], [7, "prerequisites"], [8, "prerequisites"], [15, "prerequisites"], [16, "prerequisites"], [21, "prerequisites"]], "Installing the Chart": [[2, "installing-the-chart"], [4, "installing-the-chart"], [5, "installing-the-chart"], [6, "installing-the-chart"], [7, "installing-the-chart"], [8, "installing-the-chart"]], "Uninstalling the Chart": [[2, "uninstalling-the-chart"], [4, "uninstalling-the-chart"], [5, "uninstalling-the-chart"], [6, "uninstalling-the-chart"], [7, "uninstalling-the-chart"], [8, "uninstalling-the-chart"]], "Configuration options": [[2, "configuration-options"], [4, "configuration-options"], [5, "configuration-options"], [6, "configuration-options"], [7, "configuration-options"], [8, "configuration-options"]], "Helm": [[3, "helm"]], "Contents": [[3, null], [9, null], [10, null], [12, null], [14, null], [25, null]], "Memory-QoS Plugin": [[4, "memory-qos-plugin"]], "Memtierd Plugin": [[5, "memtierd-plugin"]], "SGX EPC Limit Plugin": [[6, "sgx-epc-limit-plugin"], [17, "sgx-epc-limit-plugin"]], "Template Policy Plugin": [[7, "template-policy-plugin"]], "Topology-Aware Policy Plugin": [[8, "topology-aware-policy-plugin"]], "Deployment": [[9, "deployment"], [27, "deployment"]], "Operator": [[10, "operator"]], "Welcome to NRI Plugins documentation": [[12, "welcome-to-nri-plugins-documentation"]], "Memory plugins": [[14, "memory-plugins"]], "Memory QoS NRI plugin": [[15, "memory-qos-nri-plugin"]], "Workload configuration": [[15, "workload-configuration"], [16, "workload-configuration"]], "Plugin configuration": [[15, "plugin-configuration"], [16, "plugin-configuration"]], "Classes": [[15, "classes"], [16, "classes"]], "Unified annotations": [[15, "unified-annotations"]], "Example": [[15, "example"], [16, "example"], [27, "example"]], "Developer\u2019s guide": [[15, "developer-s-guide"], [16, "developer-s-guide"]], "Build": [[15, "build"], [16, "build"]], "Run": [[15, "run"], [16, "run"]], "Manual test": [[15, "manual-test"], [16, "manual-test"]], "Debug": [[15, "debug"], [16, "debug"]], "Deploy": [[15, "deploy"], [16, "deploy"]], "Memtierd NRI plugin": [[16, "memtierd-nri-plugin"]], "Security": [[16, "security"]], "Annotations": [[17, "annotations"]], "Dynamic Configuration": [[18, "dynamic-configuration"]], "Architecture": [[19, "architecture"]], "Overview": [[19, "overview"], [27, "overview"], [30, "overview"]], "Components": [[19, "components"]], "Node Agent": [[19, "node-agent"]], "Resource Manager": [[19, "resource-manager"]], "Cache": [[19, "cache"]], "Generic Policy Layer": [[19, "generic-policy-layer"]], "Generic Resource Controller Layer": [[19, "generic-resource-controller-layer"]], "Metrics Collector": [[19, "metrics-collector"]], "Policy Implementations": [[19, "policy-implementations"]], "Topology Aware": [[19, "topology-aware"]], "Balloons": [[19, "balloons"]], "Template": [[19, "template"]], "CPU Allocator": [[20, "cpu-allocator"]], "Topology Based Allocation": [[20, "topology-based-allocation"]], "CPU Prioritization": [[20, "cpu-prioritization"]], "Intel Speed Select Technology (SST)": [[20, "intel-speed-select-technology-sst"]], "Linux CPUFreq": [[20, "linux-cpufreq"]], "End-to-End tests": [[21, "end-to-end-tests"]], "Usage": [[21, "usage"]], "Test phases": [[21, "test-phases"]], "Test modes": [[21, "test-modes"]], "Running from scratch and quick rerun in existing virtual machine": [[21, "running-from-scratch-and-quick-rerun-in-existing-virtual-machine"]], "Custom topologies": [[21, "custom-topologies"]], "Test output": [[21, "test-output"]], "Developer\u2019s Guide": [[22, "developer-s-guide"]], "Testing": [[23, "testing"]], "Unit tests": [[24, "unit-tests"]], "Resource Policy Plugins": [[25, "resource-policy-plugins"]], "Balloons Policy": [[27, "balloons-policy"]], "How It Works": [[27, "how-it-works"]], "Configuration": [[27, "configuration"]], "Parameters": [[27, "parameters"]], "Assigning a Container to a Balloon": [[27, "assigning-a-container-to-a-balloon"]], "Disabling CPU or Memory Pinning of a Container": [[27, "disabling-cpu-or-memory-pinning-of-a-container"], [30, "disabling-cpu-or-memory-pinning-of-a-container"]], "Metrics and Debugging": [[27, "metrics-and-debugging"]], "Policies": [[28, "policies"]], "Template Policy": [[29, "template-policy"]], "Topology-Aware Policy": [[30, "topology-aware-policy"]], "Background": [[30, "background"]], "Features": [[30, "features"]], "Configuring the Policy": [[30, "configuring-the-policy"]], "Policy CPU Allocation Preferences": [[30, "policy-cpu-allocation-preferences"]], "Container CPU Allocation Preference Annotations": [[30, "container-cpu-allocation-preference-annotations"]], "Shared, Exclusive, and Isolated CPU Preference": [[30, "shared-exclusive-and-isolated-cpu-preference"]], "Implicit Hardware Topology Hints": [[30, "implicit-hardware-topology-hints"]], "Implicit Topological Co-location for Pods and Namespaces": [[30, "implicit-topological-co-location-for-pods-and-namespaces"]], "Cold Start": [[30, "cold-start"]], "Container memory requests and limits": [[30, "container-memory-requests-and-limits"]], "Reserved pool namespaces": [[30, "reserved-pool-namespaces"]], "Reserved CPU annotations": [[30, "reserved-cpu-annotations"]], "Allowing or denying mount/device paths via annotations": [[30, "allowing-or-denying-mount-device-paths-via-annotations"]], "Container Affinity and Anti-Affinity": [[30, "container-affinity-and-anti-affinity"]], "Affinity Annotation Syntax": [[30, "affinity-annotation-syntax"]], "Affinity Semantics": [[30, "affinity-semantics"]], "Examples": [[30, "examples"]], "Shorthand Notation": [[30, "shorthand-notation"]], "Setup and Usage": [[31, "setup-and-usage"]], "Setting up NRI Resource Policy": [[31, "setting-up-nri-resource-policy"]], "Dynamic Configuration with Custom Resources": [[31, "dynamic-configuration-with-custom-resources"]], "Logging and debugging": [[31, "logging-and-debugging"]]}, "indexentries": {}})