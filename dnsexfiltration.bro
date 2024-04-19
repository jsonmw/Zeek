# Jason Wild CISS 469
# Zeek/Bro Script Project
# DNS exfiltration script

@load base/protocols/dns
@load base/frameworks/notice

module DNS;

export  {
    redef enum Notice::Type += {
        Exfiltration,
    };
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if (|query| > 52)
    {
        local notice_msg = fmt("Long Domain. Possible DNS exfiltration/tunnel by %s. Offending domain name: %s",
                                 c$id$orig_h, query);

        NOTICE([$note=DNS::Exfiltration,
                 $msg=notice_msg,
                 $conn=c,
                 $sub=query,
                 ]);
    }
}