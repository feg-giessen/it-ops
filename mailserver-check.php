<?php

class EmailCheck {

    private $sock;

    private $user;

    private $domain;

    private $port = 25;

    private $max_conn_time = 30;

    private $max_read_time = 5;

    private $messages;

    private $blacklistServers = array(
        'b.barracudacentral.org',
        'spam.rbl.msrbl.net',
        'zen.spamhaus.org',
        'bl.deadbeef.com',
        'bl.emailbasura.org',
        'bl.spamcannibal.org',
        'bl.spamcop.net',
        'blackholes.five-ten-sg.com',
        'blacklist.woody.ch',
        'bogons.cymru.com',
        'cbl.abuseat.org',
        'cdl.anti-spam.org.cn',
        'combined.abuse.ch',
        'combined.rbl.msrbl.net',
        'db.wpbl.info',
        'dnsbl-1.uceprotect.net',
        'dnsbl-2.uceprotect.net',
        'dnsbl-3.uceprotect.net',
        'dnsbl.ahbl.org',
        'dnsbl.cyberlogic.net',
        'dnsbl.inps.de',
        'dnsbl.njabl.org',
        'dnsbl.sorbs.net',
        'drone.abuse.ch',
        'drone.abuse.ch',
        'duinv.aupads.org',
        'dul.dnsbl.sorbs.net',
        'dul.ru',
        'dyna.spamrats.com',
        'dynip.rothen.com',
        'http.dnsbl.sorbs.net',
        'images.rbl.msrbl.net',
        'ips.backscatterer.org',
        'ix.dnsbl.manitu.net',
        'korea.services.net',
        'misc.dnsbl.sorbs.net',
        'noptr.spamrats.com',
        'ohps.dnsbl.net.au',
        'omrs.dnsbl.net.au',
        'orvedb.aupads.org',
        'osps.dnsbl.net.au',
        'osrs.dnsbl.net.au',
        'owfs.dnsbl.net.au',
        'owps.dnsbl.net.au',
        'pbl.spamhaus.org',
        'phishing.rbl.msrbl.net',
        'probes.dnsbl.net.au',
        'proxy.bl.gweep.ca',
        'proxy.block.transip.nl',
        'psbl.surriel.com',
        'rbl.interserver.net',
        'rdts.dnsbl.net.au',
        'relays.bl.gweep.ca',
        'relays.bl.kundenserver.de',
        'relays.nether.net',
        'residential.block.transip.nl',
        'ricn.dnsbl.net.au',
        'rmst.dnsbl.net.au',
        'sbl.spamhaus.org',
        'short.rbl.jp',
        'smtp.dnsbl.sorbs.net',
        'socks.dnsbl.sorbs.net',
        'spam.abuse.ch',
        'spam.dnsbl.sorbs.net',
        'spam.spamrats.com',
        'spamlist.or.kr',
        'spamrbl.imp.ch',
        't3direct.dnsbl.net.au',
        'tor.ahbl.org',
        'tor.dnsbl.sectoor.de',
        'torserver.tor.dnsbl.sectoor.de',
        'ubl.lashback.com',
        'ubl.unsubscore.com',
        'virbl.bit.nl',
        'virus.rbl.jp',
        'virus.rbl.msrbl.net',
        'web.dnsbl.sorbs.net',
        'wormrbl.imp.ch',
        'xbl.spamhaus.org',
        'zombie.dnsbl.sorbs.net'
    );

    function logmsg($str) {
        $this->messages = $this->messages . $str . "\n";
    }

    function send($msg) {
        fwrite($this->sock, $msg . "\r\n");

        $reply = fread($this->sock, 2082);

        $this->logmsg('>> ' . $msg);
        $this->logmsg('<< ' . $reply);

        return $reply;
    }

    /**
     * Query DNS server for MX entries
     * @param $domain
     * @return array
     */
    function queryMX($domain) {
        $hosts = array();
        $preferences = array();

        getmxrr($domain, $hosts, $preferences);

        return array($hosts, $preferences);
    }

    /**
     * Parse user and domain from e-mail address.
     *
     * @param $email
     */
    function setDomainData($email) {
        $parts = explode('@', $email);

        $this->domain = array_pop($parts);
        $this->user = implode('@', $parts);
    }

    function parseRcptReply($reply) {
        $matches = array();

        preg_match('/^([0-9]{3}) /ims', $reply, $matches);
        $code = isset($matches[1]) ? $matches[1] : '';

        return ($code == '250' || $code == '451' || $code == '452');
    }

    function checkBlacklist($mxHost) {
        $ip = gethostbyname ($mxHost);
        $ip_revers = join('.', array_reverse(explode('.', $ip)));

        $result = array();

        foreach($this->blacklistServers as $server) {
            $bl_query = $ip_revers . '.' . $server;
            $blacklist = gethostbyname($bl_query);

            if ($bl_query !== $blacklist) {
                $result[] = $server;
            }
        }

        return $result;
    }

    /**
     * Validate the email id
     * @return the info
     */
    function validate($email) {

        $result = array();

        // set email and domain
        $this->setDomainData($email);

        $result['tested_mail'] = $this->user . '@' . $this->domain;

        // retrieve SMTP Server via MX query on domain
        list($hosts, $mxPreference) = $this->queryMX($this->domain);

        if (empty($hosts))
            die("No MX servers found.\n");

        // retrieve MX priorities
        $mxServers = array();
        for ($n = 0; $n < count($hosts); $n++) {
            $mxServers[$hosts[$n]] = $mxPreference[$n];
        }

        // sort by preference
        asort($mxServers);

        $result['blacklist'] = array();

        // check blacklists
        foreach ($mxServers as $host => $preference) {
            $blacklist = $this->checkBlacklist($host);

            $mxServers[$host] = array(
                'preference' => $preference,
                'blacklist' => $blacklist);

            if (!empty($blacklist)) {
                $result['blacklist'][$host] = $blacklist;
            }
        }

        // time out
        $timeout = $this->max_conn_time;
        $test_host = null;

        foreach ($mxServers as $host => $host_data) {

            // connect to server
            $this->logmsg("trying $host:$this->port...");

            $err_no = $err_str = null;
            if ($this->sock = fsockopen($host, $this->port, $err_no, $err_str, (float)$timeout)) {
                stream_set_timeout($this->sock, $this->max_read_time);
                $mxServers[$host]['tested'] = true;
                $result['tested_server'] = $host;

                break;
            }
        }

        // did we get a TCP socket
        if (!$this->sock) {
            delete($mxServers[$result['tested_server']]['tested']);
            delete($result['tested_server']);
            $result['sock_error'] = true;
        } else {
            $result['sock_error'] = false;

            $reply = fread($this->sock, 2082);
            $this->logmsg('<< ' .$reply);

            $this->send('HELO mx-monitor.example.com');

            // identify sender
            $this->send("MAIL FROM: <mail-check@example.com>");

            // test open relay
            $reply = $this->send('RCPT TO: <test@example.com>');
            $result['open_relay'] = $this->parseRcptReply($reply);

            $this->send("RSET");

            // identify sender
            $this->send("MAIL FROM: <mail-check@example.com>");

            // test valid recipient
            $reply = $this->send('RCPT TO: <' . $this->user . '@' . $this->domain . '>');
            $result['accepts_valid'] = $this->parseRcptReply($reply);

            $this->send("RSET");

            // quit
            $this->send("quit");

            // close socket
            fclose($this->sock);
        }

        // add this mx servers to result
        $result['servers'] = $mxServers;

        // add messages
        $result['messages'] = $this->messages;

        return $result;
    }
}

if (!isset($argv[1]))
    die("Specify email to test as argument.\n");

$tester = new EmailCheck();
$result = $tester->validate($argv[1]);

$notifications = array();

if (!$result['sock_error']) {

    if ($result['open_relay']) {
        $notifications[] = $result['tested_server'] . ' is configured as open relay!';
    }

    if (!$result['accepts_valid']) {
        $notifications[] = $result['tested_server'] . ' does not accept emails to ' . $result['tested_mail'];
    }
}

if (!empty($result['blacklist'])) {
    foreach ($result['blacklist'] as $server => $blacklists) {
        $notifications[] = 'Blacklisted ' . $server . ': ' . implode(', ', $blacklists);
    }
}

if (!empty($notifications)) {
    echo implode("\n", $notifications);

    echo "\n";
    echo $result['messages'];
}
?>