@load base/frameworks/notice
@load base/protocols/ftp
@load local-metrics

module FTP;

export {
    redef enum Notice::Type += { FTP_AuthBruteForce, FTP_Auth_Failure };
    redef enum Metrics::ID += { FTP_BadLogin };
}

event bro_init()
{
    Metrics::add_filter(FTP_BadLogin, [$log=T,
            $notice_threshold=10,
            $break_interval=2mins,
            $note=FTP_AuthBruteForce]);
}

event ftp_reply(c: connection, code: count, msg: string, cont_resp: bool) &priority=-1
{
    set_ftp_session(c);

    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local cmd = to_upper(c$ftp$cmdarg$cmd);
    local bad_auth = F;
    local reset_auth = F;

    if (cmd == "PASS") {
      if (code == 530) {
        bad_auth = T;
      } else if (code == 230) {
        reset_auth = T;
      }
    }

    if (reset_auth == T) {
      Metrics::reset_data(FTP_BadLogin,
        [$host=src]);
    }

    if (bad_auth == T) {
        NOTICE([$note = FTP_Auth_Failure, $conn = c, $msg = fmt("USER=<%s>/%s", c$ftp$user, msg)]);
        Metrics::add_data(FTP_BadLogin,
            [$host=src], 1);
    }
}

