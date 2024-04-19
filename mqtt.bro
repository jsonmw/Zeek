# MQTT Subscribe Script

redef ignore_checksums = T;

# Creates the Subscribe Notice type
export  {
    redef enum Notice::Type += {
        Subscribe,
    };
}

# Inspects the packet and extracts payload, which it then determines whether or not the TCP packet is MQTT,
# and checks for subscriptions to new topics. If one is found, a notice is generated for the log.

event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count, ack: count, len: count; payload: string)
{
    local size = |payload|;
    local i = 0;
    local offset = 6;
    while (i < size)
    {
        if (payload[i] == "\x82") {  # Checks for MQTT Protocol header
            local j = i + offset;

            # Nested loop to inspect MQTT payload until terminator byte found
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
