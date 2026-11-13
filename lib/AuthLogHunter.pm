package AuthLogHunter;
use strict;
use warnings;
use Time::Local qw(timegm);
use JSON::PP ();
our $VERSION = '1.0.0';

my %MON = (Jan=>0,Feb=>1,Mar=>2,Apr=>3,May=>4,Jun=>5,Jul=>6,Aug=>7,Sep=>8,Oct=>9,Nov=>10,Dec=>11);

# Parse OpenSSH lines from syslog-style auth logs. Returns list of events.
sub parse {
    my ($text, $year) = @_;
    $year //= 1900 + (gmtime)[5];
    my @ev;
    my $n = 0;
    for my $line (split /\n/, $text) {
        $n++;
        next unless $line =~ /^(\w{3})\s+(\d+)\s+(\d\d):(\d\d):(\d\d)\s+(\S+)\s+sshd\[\d+\]:\s+(.*)$/;
        my ($mon, $d, $H, $M, $S, $host, $msg) = ($1, $2, $3, $4, $5, $6, $7);
        next unless exists $MON{$mon};
        my $ts = eval { timegm($S, $M, $H, $d, $MON{$mon}, $year) } // next;
        my %e = (ts => $ts, host => $host, line => $n);
        if ($msg =~ /^Failed (\S+) for (invalid user )?(\S+) from (\S+) port \d+/) {
            @e{qw(type method user ip invalid)} = ('fail', $1, $3, $4, $2 ? 1 : 0);
        } elsif ($msg =~ /^Accepted (\S+) for (\S+) from (\S+) port \d+/) {
            @e{qw(type method user ip)} = ('ok', $1, $2, $3);
        } elsif ($msg =~ /^Invalid user (\S+) from (\S+)/) {
            @e{qw(type user ip)} = ('invalid', $1, $2);
        } else { next }
        push @ev, {%e};
    }
    return \@ev;
}

# Detect brute force, spraying, and success after failures.
sub analyze {
    my ($ev, %o) = @_;
    my $window = $o{window} // 600;
    my $min = $o{min_failures} // 10;
    my (%by, @out);
    push @{ $by{$_->{ip}} }, $_ for grep { defined $_->{ip} } @$ev;
    for my $ip (sort keys %by) {
        my @e = sort { $a->{ts} <=> $b->{ts} } @{ $by{$ip} };
        my @fails = grep { $_->{type} eq 'fail' || $_->{type} eq 'invalid' } @e;
        next unless @fails;
        # sliding window of failures
        my ($best, $i) = (0, 0);
        for my $j (0 .. $#fails) {
            $i++ while $fails[$j]{ts} - $fails[$i]{ts} > $window;
            $best = $j - $i + 1 if $j - $i + 1 > $best;
        }
        my %users = map { $_->{user} => 1 } @fails;
        my $nusers = keys %users;
        my $inv = grep { $_->{invalid} || $_->{type} eq 'invalid' } @fails;
        my @oks = grep { $_->{type} eq 'ok' } @e;
        my ($after) = grep { my $o = $_; grep { $_->{ts} <= $o->{ts} } @fails } @oks;
        my @why; my $sev = 'low'; my $kind;
        if ($best >= $min) {
            $kind = $nusers >= 5 && $best / $nusers < 4 ? 'password-spraying' : 'brute-force';
            push @why, "$best failed attempts within " . int($window / 60) . " minutes";
            push @why, "$nusers distinct usernames tried" if $nusers > 1;
            push @why, "$inv attempts for users that do not exist" if $inv;
            $sev = 'medium';
        }
        if ($after && @fails >= 3) {
            $kind //= 'success-after-failures';
            $sev = 'critical';
            push @why, "login ACCEPTED for '$after->{user}' via $after->{method} after " . scalar(grep { $_->{ts} <= $after->{ts} } @fails) . " failures from the same address";
            push @why, "successful login is for root" if $after->{user} eq 'root';
        }
        next unless $kind;
        push @out, { ip => $ip, kind => $kind, severity => $sev, failures => scalar(@fails), users => $nusers,
                     first => $fails[0]{ts}, last => $fails[-1]{ts}, reasons => \@why };
    }
    my %rank = (critical => 0, medium => 1, low => 2);
    return [ sort { $rank{$a->{severity}} <=> $rank{$b->{severity}} || $b->{failures} <=> $a->{failures} || $a->{ip} cmp $b->{ip} } @out ];
}

sub _t { my @t = gmtime($_[0]); sprintf('%04d-%02d-%02d %02d:%02d:%02dZ', $t[5] + 1900, $t[4] + 1, @t[3, 2, 1, 0]) }

sub text {
    my ($fs) = @_;
    return "No suspicious SSH activity.\n" unless @$fs;
    my $o = '';
    for my $f (@$fs) {
        $o .= sprintf("%-8s %-22s %-16s %d failures, %d users, %s to %s\n", uc $f->{severity}, $f->{kind}, $f->{ip}, $f->{failures}, $f->{users}, _t($f->{first}), _t($f->{last}));
        $o .= "           - $_\n" for @{ $f->{reasons} };
    }
    return $o;
}

sub json { JSON::PP->new->canonical->pretty->encode($_[0]) }

sub _h { my $s = shift; $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g; $s }

sub html {
    my ($fs, $n) = @_;
    my $rows = join '', map {
        my $f = $_;
        "<tr><td class=\"$f->{severity}\">$f->{severity}</td><td>" . _h($f->{kind}) . "</td><td>" . _h($f->{ip}) . "</td><td>$f->{failures}</td><td>$f->{users}</td><td>" . _h(join('; ', @{ $f->{reasons} })) . "</td></tr>"
    } @$fs;
    return <<"HTML";
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'"><title>auth-log-hunter</title><style>:root{color-scheme:dark}body{margin:0;padding:28px;background:#0e1319;color:#e8eef5;font:14px/1.5 system-ui,sans-serif}h1{margin:0 0 4px}.sub{color:#8b98a8}table{border-collapse:collapse;width:100%;margin-top:14px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a3441;vertical-align:top}th{color:#8b98a8}td.critical{color:#f85149;font-weight:700}td.medium{color:#e3b341;font-weight:700}td.low{color:#8b98a8}</style></head><body><h1>auth-log-hunter</h1><p class="sub">SSH brute force, password spraying and compromise detection from auth logs. Perl, core modules only. Report on a synthetic log with $n events.</p><table><tr><th>Severity</th><th>Kind</th><th>Source</th><th>Failures</th><th>Users</th><th>Why</th></tr>$rows</table></body></html>
HTML
}

1;
