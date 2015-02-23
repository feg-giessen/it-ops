switches = [ 1, 2, 3, 4, 5 ]

template = """# filter

filter f_switch{id} {{ netmask("192.168.0.1{id}/32"); }};

# destination

destination d_switch{id}_dbg {{ file("{path}/switch{id}/debug.log"); }};
destination d_switch{id}_info {{ file("{path}/switch{id}/info.log"); }};
destination d_switch{id}_notice {{ file("{path}/switch{id}/notice.log"); }};
destination d_switch{id}_warn {{ file("{path}/switch{id}/warning.log"); }};
destination d_switch{id}_err {{ file("{path}/switch{id}/error.log"); }};
destination d_switch{id}_crit {{ file("{path}/switch{id}/critical.log"); }};
destination d_switch{id}_other {{ file("{path}/switch{id}/other.log"); }};

# logs

log {{ source(s_udp); filter(f_switch{id}); filter(f_dbg); destination(d_switch{id}_dbg); flags(final); }};
log {{ source(s_udp); filter(f_switch{id}); filter(f_info); destination(d_switch{id}_info); flags(final); }};
log {{ source(s_udp); filter(f_switch{id}); filter(f_notice); destination(d_switch{id}_notice); flags(final); }};
log {{ source(s_udp); filter(f_switch{id}); filter(f_warn); destination(d_switch{id}_warn); flags(final); }};
log {{ source(s_udp); filter(f_switch{id}); filter(f_err); destination(d_switch{id}_err); flags(final); }};
log {{ source(s_udp); filter(f_switch{id}); filter(f_crit); destination(d_switch{id}_crit); flags(final); }};
log {{ source(s_udp); filter(f_switch{id}); filter(f_feg_other); destination(d_switch{id}_other); flags(final); }};
""" 

for switchId in switches:
    context = {
     "id":`switchId`,
     "path":'/var/log/syslog-ng'
     } 
    with  open('conf.d/switch' + `switchId` + '.conf','w') as f:
        f.write(template.format(**context))
