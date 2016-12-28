import iptc

#10.8.59.206
#192.168.5.113  -> rule.src = "149.154.167.91/149.154.167.91"
table = iptc.Table(iptc.Table.FILTER)


# Engelleme
rule = iptc.Rule()
rule.in_interface = "wlp4s0"
rule.src = "149.154.167.91/149.154.167.91"
rule.dst = "192.168.5.113"
rule.protocol = "tcp"
match = iptc.Match(rule, "tcp")
target = iptc.Target(rule, "DROP")
rule.add_match(match)
rule.target = target
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)



'''
rule = iptc.Rule()
rule.in_interface = "wlp4s0"
rule.src = "192.168.118.128"
rule.dst = "104.244.42.8"
rule.protocol = "tcp"
match = iptc.Match(rule, "tcp")
target = iptc.Target(rule, "REJECT")
rule.add_match(match)
rule.target = target
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "OUTPUT")
chain.insert_rule(rule)
'''

# telegram: 149.154.167.91
'''
rule = iptc.Rule()
rule.in_interface = "wlp4s0"
rule.src = "52.0.0.0/52.255.255.255"
rule.dst = "0.0.0.0/255.255.255.255"
rule.protocol = "tcp"

match = iptc.Match(rule, "tcp")
rule.add_match(match)

match = iptc.Match(rule, "iprange")
match.src_range = "52.0.0.0-52.255.255.255"
match.dst_range = "10.8.59.206"
rule.add_match(match)

target = iptc.Target(rule, "DROP")
rule.target = target
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)

'''


'''
rule = iptc.Rule()
rule.in_interface = "wlp4s0"
rule.src = "149.0.0.0/149.255.255.255"
rule.dst = "0.0.0.0/255.255.255.255"
rule.protocol = "tcp"

match = iptc.Match(rule, "tcp")
rule.add_match(match)

match = iptc.Match(rule, "iprange")
match.src_range = "149.0.0.0-149.255.255.255"
match.dst_range = "10.8.59.206-10.255.255.255"
rule.add_match(match)

target = iptc.Target(rule, "DROP")
rule.target = target
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)
'''
