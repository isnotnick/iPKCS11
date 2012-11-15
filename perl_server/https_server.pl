#!/usr/bin/perl -w
use lib "/opt/local/lib/perl5/site_perl/5.12.4";
use JSON;
use HTTP::Daemon::SSL;
use Switch;

use pkcs11;

while(1) {
    my $d = HTTP::Daemon::SSL->new(
        SSL_key_file => "CERTS/server.key",
        SSL_cert_file => "CERTS/server.crt",
        LocalAddr => '127.0.0.1',
        LocalPort => 8000,
    ) || die;

    print "Please contact me at: <URL:", $d->url, ">\n\n";

    while (my $c = $d->accept) {
        while (my $r = $c->get_request) {
            if ($r->method eq 'POST') {
                my $json;
                my $method;
                my $params;

                eval {
                    $json = decode_json($r->content);
                    $method = $json->{"method"};
                    $params = $json->{"params"};
                    1;
                } or do {
                    print "error while parsing ", $r->content, "\nresetting state\n";
                    next;
                };

                print "calling        $method with ", to_json($params), "\n";
                my $reply;
                switch ($method) {
                    case "C_GetInfo"           { $reply = C_GetInfo($params); }
                    case "C_GetSlotList"       { $reply = C_GetSlotList($params); }
                    case "C_GetTokenInfo"      { $reply = C_GetTokenInfo($params); }
                    case "C_FindObjectsInit"   { $reply = C_FindObjectsInit($params); }
                    case "C_FindObjects"       { $reply = C_FindObjects($params); }
                    case "C_FindObjectsFinal"  { $reply = C_FindObjectsFinal($params); }
                    case "C_GetAttributeValue" { $reply = C_GetAttributeValue($params); }
                    case "C_Login"             { $reply = C_Login($params); }
                    case "C_OpenSession"       { $reply = C_OpenSession($params); }
                    case "C_SignInit"          { $reply = C_SignInit($params); }
                    case "C_Sign"              { $reply = C_Sign($params); }
                    case "C_Finalize"          { $reply = C_Finalize($params); }
                    case "C_CloseSession"      { $reply = C_CloseSession($params); }
                    else                       { $reply = {}; print "unknown method $method\n"; }
                }

                my $replyString = to_json($reply);

                print "returning from $method with $replyString\n\n";

                my $rs = new HTTP::Response(RC_OK);
                $rs->content($replyString);
                $rs->content_type("application/json");
                $c->send_response($rs);
            } else {
                print "method:", $r->method;
                my $rs = new HTTP::Response(RC_OK);
                $rs->content("<html><body></body></html>\n");
                $rs->content_type("text/html");
                $c->send_response($rs);
            }
        }
        $c->close;
        undef($c);
    }

    print "Server rebooted!\n";
}
