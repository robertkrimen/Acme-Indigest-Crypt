package Acme::Indigest::Crypt;
# ABSTRACT: Acme::Indigest::Crypt

use strict;
use warnings;

use Crypt::Passwd::XS;
use Digest::SHA qw/ sha512_hex /;

sub digest {
    my $self = shift;
    my $passphrase = shift;
    my $limit = shift || 5000;
    die "--<<>>---+__-_-_---+<>\n" unless $limit =~ m/^\d+$/;
    $limit = 1000 if $limit < 1000;

    my $result = sha512_hex( $passphrase );
    for ( 1 .. $limit ) {
        $result .= sha512_hex( $result );
        if ( $_ == $limit || $_ % 5000 == 0 ) {
            $result = substr $result, -512;
        }
    }

    return Crypt::Passwd::XS::unix_sha512_crypt( $result, '' );
}

1;
