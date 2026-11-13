use strict;
use warnings;
use Test::More;
use FindBin qw($Bin);
use lib "$Bin/../lib";
use AuthLogHunter;

sub line { my ($s, $msg) = @_; sprintf("Nov 12 02:%02d:%02d web01 sshd[100]: %s\n", int($s / 60), $s % 60, $msg) }
sub fails { my ($n, $user, $ip, $inv) = @_; join '', map { line($_, "Failed password for " . ($inv ? 'invalid user ' : '') . "$user from $ip port 4000 ssh2") } 1 .. $n }

my $e = AuthLogHunter::parse(line(1, 'Failed password for root from 1.2.3.4 port 22 ssh2') . line(2, 'Accepted publickey for bob from 5.6.7.8 port 22 ssh2') . line(3, 'Invalid user x from 9.9.9.9 port 22') . "garbage line\n", 2026);
is(scalar @$e, 3, 'parses three sshd events and skips garbage');
is($e->[0]{type}, 'fail', 'failure'); is($e->[1]{method}, 'publickey', 'method'); is($e->[2]{type}, 'invalid', 'invalid user');

my $f = AuthLogHunter::analyze(AuthLogHunter::parse(fails(30, 'admin', '1.1.1.1'), 2026));
is(scalar @$f, 1, 'brute force detected'); is($f->[0]{kind}, 'brute-force', 'kind'); is($f->[0]{severity}, 'medium', 'medium without success');

is(scalar @{ AuthLogHunter::analyze(AuthLogHunter::parse(fails(4, 'admin', '1.1.1.1'), 2026)) }, 0, 'a few typos are ignored');

my $ok = AuthLogHunter::analyze(AuthLogHunter::parse(fails(12, 'root', '2.2.2.2') . line(100, 'Accepted password for root from 2.2.2.2 port 22 ssh2'), 2026));
is($ok->[0]{severity}, 'critical', 'success after failures is critical');
like(join(' ', @{ $ok->[0]{reasons} }), qr/root/, 'mentions root');

my $typo = AuthLogHunter::analyze(AuthLogHunter::parse(fails(2, 'maria', '3.3.3.3') . line(50, 'Accepted password for maria from 3.3.3.3 port 22 ssh2'), 2026));
is(scalar @$typo, 0, 'two typos then success is normal');

my $spray = join '', map { line(1 + $_, "Failed password for invalid user u$_ from 4.4.4.4 port 22 ssh2") . line(30 + $_, "Failed password for u$_ from 4.4.4.4 port 22 ssh2") } 1 .. 8;
my $s = AuthLogHunter::analyze(AuthLogHunter::parse($spray, 2026));
is($s->[0]{kind}, 'password-spraying', 'spraying: many users, few tries each');

my $slow = join '', map { line($_ * 120, "Failed password for admin from 5.5.5.5 port 22 ssh2") } 1 .. 25;
is(scalar @{ AuthLogHunter::analyze(AuthLogHunter::parse($slow, 2026), window => 300) }, 0, 'slow failures outside the window are not a burst');
is(scalar @{ AuthLogHunter::analyze(AuthLogHunter::parse($slow, 2026), window => 7200) }, 1, 'window is configurable');

like(AuthLogHunter::html([{ ip => '<x>', kind => 'k', severity => 'low', failures => 1, users => 1, reasons => ['<script>'] }], 1), qr/&lt;x&gt;/, 'html escapes');
unlike(AuthLogHunter::html([{ ip => '1', kind => 'k', severity => 'low', failures => 1, users => 1, reasons => ['<script>'] }], 1), qr/<script>/, 'html escapes reasons');
like(AuthLogHunter::json([{ a => 1 }]), qr/"a"\s*:\s*1/, 'json');

open(my $fh, '<', "$Bin/../examples/auth.log") or die;
my $sample = AuthLogHunter::analyze(AuthLogHunter::parse(do { local $/; <$fh> }, 2026));
is(scalar @$sample, 3, 'sample log: three offenders');
is($sample->[0]{severity}, 'critical', 'sample log: compromise first');
done_testing;
