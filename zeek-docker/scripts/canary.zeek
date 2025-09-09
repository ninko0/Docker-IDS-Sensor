@load base/frameworks/notice

module Canary;

export {
  # IPs des honeypots (modifiable à chaud avec redef)
  const honeypot_addrs: set[addr] = { 192.168.69.216, 192.168.69.217 } &redef;

  const http_ports:  set[port] = { 80/tcp } &redef;
  const ssh_ports:   set[port] = { 22/tcp } &redef;
  const ftp_ports:   set[port] = { 21/tcp } &redef;
  const mysql_ports: set[port] = { 3306/tcp } &redef;

  redef enum Notice::Type += {
    HoneyServiceConn
  };
}

event connection_established(c: connection)
    {
    if ( c$id$resp_h in honeypot_addrs )
        {
        local p = c$id$resp_p;
        local svc = "";

        if ( p in http_ports )  svc = "HTTP";
        if ( p in ssh_ports )   svc = "SSH";
        if ( p in ftp_ports )   svc = "FTP";
        if ( p in mysql_ports ) svc = "MYSQL";

        if ( svc != "" )
            NOTICE([$note=HoneyServiceConn,
                    $msg=fmt("Conn to honeypot %s %s:%s from %s:%s",
                             svc, c$id$resp_h, p, c$id$orig_h, c$id$orig_p),
                    $conn=c]);
        }
    }

# Optionnel : Notice aussi quand Zeek confirme le protocole applicatif.
event protocol_confirmation(c: connection, proto: string)
    {
    if ( c$id$resp_h in honeypot_addrs && proto in set("http","ssh","ftp","mysql") )
        NOTICE([$note=HoneyServiceConn,
                $msg=fmt("App-layer %s to honeypot %s from %s", proto, c$id$resp_h, c$id$orig_h),
                $conn=c]);
    }
