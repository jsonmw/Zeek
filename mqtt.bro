# Jason Wild CISS 469
# Zeek/Bro Script Project
# DNS exfiltration script

redef ignore_checksums = T;
module MQTT;

export  {
    redef enum Notice::Type += {
        Subscribe,
    };
}

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count; payload: string)
{
    local size = |payload|;
    local i = 0;
    local offset = 6;
    while (i < size)
    {
        if (payload[i] == "\x82") {
            local j = i + offset;

            while (payload[j] != "\x00" )
            {
                j+=1;
            }
            local topic = payload[i+offset:j];

            local notice_msg = fmt("%s attempts to subscribe to %s topics.",
                                c$id$orig_h, topic);
            
            NOTICE([$note=MQTT::Subscribe,
                $msg=notice_msg,
                $conn=c,
                ]);
            i=i+j;
        }
        i += 1;
    }
}