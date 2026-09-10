# Detects outbound HTTP to the specific C2 domain observed in this incident's
# staging/exfil connection. Domain-based, not IP-based, since IPs are far
# easier for an attacker to rotate than a fixed callback hostname.
export {
    redef enum Notice::Type += {
        C2_Domain_Contacted,
    };
}

const c2_domains: set[string] = {
    "sync-v1.updates-example.invalid",
} &redef;

event http_header(c: connection, is_orig: bool, original_name: string, name: string, value: string)
    {
    if ( name == "HOST" && value in c2_domains )
        {
        NOTICE([$note=C2_Domain_Contacted,
                $conn=c,
                $msg=fmt("Outbound HTTP request to known C2 domain: %s", value),
                $identifier=cat(c$id$orig_h, value)]);
        }
    }
