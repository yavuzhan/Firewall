import iptc


table = iptc.Table(iptc.Table.FILTER)
#chain = table.create_chain("testchain") # To create a new chain in the FILTER table:
#print (table.name)  #To access a table:

'''
# This creates a rule that will match TCP packets coming in on eth0, with a source IP address of 192.168.1.0/255.255.255.0.
rule = iptc.Rule()
rule.in_interface = "wlp4s0"
rule.src = "104.16.53.4/173.241.240.143"
rule.protocol = "tcp"
match = iptc.Match(rule, "tcp")
target = iptc.Target(rule, "REJECT")
rule.add_match(match)
rule.target = target
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)


'''

#A match is like a filter matching certain packet attributes,
#while a target tells what to do with the packet (drop it, accept it, transform it somehow, etc).
#One can create a match or target via a Rule:
'''
rule = iptc.Rule()
m = rule.create_match("tcp")
t = rule.create_target("DROP")
'''

'''
Match and target parameters can be changed after creating them.
 It is also perfectly valid to create a match or target via instantiating them with their constructor,
  but you still need a rule and you have to add the matches and the target to their rule manually:

 rule = iptc.Rule()
 match = iptc.Match(rule, "tcp")
 target = iptc.Target(rule, "DROP")
 rule.add_match(match)
 rule.target = target
'''

# Matches are optional, but we can add multiple matches to a rule. In the following example we will do that, using the iprange and the tcp matches:
'''
rule = iptc.Rule()
rule.protocol = "tcp"
rule.src = "192.30.253.124/192.30.253.125"
match = iptc.Match(rule, "tcp")
#match.dport = "22"
rule.add_match(match)
#match = iptc.Match(rule, "ip_range")
#match.src_range = "192.30.253.124-192.30.253.125"
#match.dst_range = "172.22.33.106"

rule.add_match(match)
rule.target = iptc.Target(rule, "ACCEPT")
chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
chain.insert_rule(rule)
'''


# You can of course also check what a rule's source/destination address, in/out inteface etc is. To print out all rules in the FILTER table:
