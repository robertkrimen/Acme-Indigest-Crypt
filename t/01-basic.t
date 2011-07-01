#!/usr/bin/env perl

use strict;
use warnings;

use Test::Most;

use Acme::Indigest::Crypt;

for (split m/\n/, <<'_END_' ) {
Xyzzy:5000:$6$$/V7NpvudKckYkuIXk1lEdOl8g/aFTcJeWykFpRmA5GJhAqDOVV2FaI2w6wM1WvdIJP53oUw8kKSfcB3NJFqa71
Xyzzy::$6$$/V7NpvudKckYkuIXk1lEdOl8g/aFTcJeWykFpRmA5GJhAqDOVV2FaI2w6wM1WvdIJP53oUw8kKSfcB3NJFqa71
Xyzzy:1000:$6$$ljycuoNKlwP2ymZTzQOPpmNH38UENY63VRV0S5xHUSeykFamQHsGQ1ejFfuQSRcPmWuQGnqw9pO0zQt0q2Iwi0
Xyzzy:500:$6$$ljycuoNKlwP2ymZTzQOPpmNH38UENY63VRV0S5xHUSeykFamQHsGQ1ejFfuQSRcPmWuQGnqw9pO0zQt0q2Iwi0
Xyzzy:10000:$6$$B4bDfwlxHChL0cps.0vlFoojIMNuZ88kis6G5fQ/ILktfmlxWQDFwI2lAB.N3Qfg3eXfK.1wxKtW9PxleBOgv0
Alice::$6$$ave8vhsKeYEXNvflBRwSXnicahjYFOzCSsqgWGk.DFLRFDcpapr7ulEtbhQHTo.xN7ytAS/nbp1agrMpH2HVY.
Bob::$6$$7tJafuu5CqNJXdDituK3NLx3TRPlsbGQGBcDNVCSbiVCXfFDjT.Nr85XrX.TMfKM3ppKTlSd7t6ji4tIt3uhj1
_END_
    next unless my ( $passphrase, $limit, $want ) = split ':', $_, 3;

    my $have = Acme::Indigest::Crypt->digest( $passphrase, $limit );
    is( $want, $have, "$passphrase => $limit" );
}

done_testing;
