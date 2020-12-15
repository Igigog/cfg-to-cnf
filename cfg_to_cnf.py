import re


def parse(cfg):
    parsed_cfg = {}
    for rule in str.split(cfg, "\n"):
        if rule == "":
            continue
        rule = re.sub(r"\s+", "", rule)
        parts = rule.split("->")
        parsed_cfg[parts[0]] = parts[1].split("|")
    return parsed_cfg


def is_nullable(parsed_cfg, v, pre=""):
    for rule in parsed_cfg[v]:
        if rule == "e":
            return True
        if len(rule) == 1 and rule == rule.upper():
            if rule == pre:
                continue
            if is_nullable(parsed_cfg, rule, pre=v):
                return True
    return False


def err(cfg):
    alt = set('Sneu') if 'Sneu' in cfg else set('S')
    while True:
        tmp = set()
        for rules in alt:
            for rule in cfg[rules]:
                new = "".join(x for x in rule if not x.islower())
                for v in new:
                    tmp.add(v)
        if len(tmp.difference(alt)) == 0:
            return alt
        else:
            for item in tmp:
                alt.add(item)


def co_err(cfg):
    alt = set()
    while True:
        tmpset = set()
        for k, v in cfg.items():
            for rule in v:
                if rule == rule.lower():
                    tmpset.add(k)
                else:
                    tmp = True
                    for x in rule:
                        if not x.islower() and x not in alt:
                            tmp = False
                    if tmp:
                        tmpset.add(k)
        if len(tmpset.difference(alt)) == 0:
            return alt
        else:
            for item in tmpset:
                alt.add(item)


def eliminate_useless(cfg):
    erreichbar = err(cfg)
    coerr = co_err(cfg)

    tmp = []
    for k in cfg:
        if k not in erreichbar.intersection(coerr):
            tmp.append(k)
    for k in tmp:
        cfg.pop(k)

    return cfg


def eliminate_eps(cfg):
    nullables = set(x for x in cfg if is_nullable(cfg, x))
    for k, rules in cfg.items():
        for rule in rules:
            for index, x in enumerate(rule):
                if x in nullables:
                    new_rule = rule[:index] + rule[index+1:] if len(rule) > 1 else "e"
                    rules.append(new_rule)

    for k, rules in cfg.items():
        cfg[k] = list(set(rules).difference(set('e')))
    return cfg


def change_to_upper(cfg):
    new_rules = {}
    for k, rules in cfg.items():
        tmp_rules = []
        for rule in rules:
            tmp_rule = ""
            for x in rule:
                if x.islower() and x not in new_rules:
                    new_rules[x] = str(len(new_rules))
                tmp_rule += x if not x.islower() else new_rules[x]
            tmp_rules.append(tmp_rule)
        cfg[k] = tmp_rules
    for rule, k in new_rules.items():
        cfg[k] = [rule, ]
    return cfg


def eliminate_chain(cfg):
    for k, rules in cfg.items():
        new_rules = []
        for rule in rules:
            if len(rule) == 1 and not rule.islower():
                new_rules += cfg[rule]
        tmp = set()
        for rule in rules + new_rules:
            if len(rule) != 1 or not rule.isupper():
                tmp.add(rule)
        cfg[k] = list(tmp)
    return cfg


def to_chomsky(cfg):
    new_rules = {}
    for k, rules in cfg.items():
        for i, rule in enumerate(rules):
            if not rule.islower() and not len(rule) < 3:
                cfg[k][i] = rule[0] + f"(H_{str(len(new_rules)+1)})"
                rule = rule[1:]
                while len(rule) > 2:
                    new_rule = rule[0] + f"(H_{str(len(new_rules)+2)})"
                    new_rules[f"(H_{str(len(new_rules) + 1)})"] = [new_rule,]
                    rule = rule[1:]
                new_rules[f"(H_{str(len(new_rules)+1)})"] = [rule[len(rule)-2:],]
    for k, v in new_rules.items():
        cfg[k] = v
    return cfg


def cfg_to_cnf(cfg):
    cfg = parse(cfg)
    if is_nullable(cfg, "S"):
        cfg["Sneu"] = ['S', 'e']
    cfg = eliminate_useless(cfg)
    cfg = eliminate_eps(cfg)
    cfg = change_to_upper(cfg)
    cfg = eliminate_chain(cfg)
    cfg = eliminate_useless(cfg)
    cfg = to_chomsky(cfg)
    return cfg


def print_beautiful(cnf):
    s = ""
    for k, rules in cnf.items():
        s = s + k + " ->"
        for k, rule in enumerate(rules):
            if k > 0:
                s = s + " |"
            s = s + " " + rule
        s += "\n"
    print(s)


cfg_lul = """
S -> ccAabB | bcaCB | cBcD
A -> Aba | bb | aCa
B -> BC | e | c
C -> bbCa | ACaa | B| ac
D -> DD | Aaa
E -> cB | b | e
"""

print_beautiful(cfg_to_cnf(cfg_lul))
