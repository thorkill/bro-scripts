
@load base/frameworks/notice
@load base/utils/site

module DNS;

export {
  redef enum Notice::Type += {
    Possible_Blacklist_OurIP,
    DNS_Excessive_IN_ANY_Count,
  };

  redef enum Metrics::ID += { DNS_IN_ANY_Src };

}

event bro_init()
{
    Metrics::add_filter(DNS_IN_ANY_Src, [$log=T,
      $notice_threshold=100,
      $break_interval=3mins,
      $note=DNS_Excessive_IN_ANY_Count]);
}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, str: string) &priority=-3
  {
    local ips: string_array;
    if (/.*http.*/ in str) {
      ips = find_ip_addresses(str);
      for (a in ips) {
        if (Site::is_local_addr(to_addr(ips[a]))) {
          NOTICE([$note=Possible_Blacklist_OurIP,
                $msg=fmt("%s - %s.", ips[a], str),
                $conn=c,
                $identifier=cat(a,ans$query)]);
        }
      }
    }
  }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) &priority=0
  {
  set_session(c, msg, T);

  if (qtype == 255) {
    Metrics::add_data(DNS_IN_ANY_Src, [$host=c$id$orig_h], 1);
    }
  }
