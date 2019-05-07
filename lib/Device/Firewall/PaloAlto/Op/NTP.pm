package Device::Firewall::PaloAlto::Op::NTP;

use strict;
use warnings;
use 5.010;

use parent qw(Device::Firewall::PaloAlto::JSON);

use Device::Firewall::PaloAlto::Errors qw(ERROR);

# VERSION
# PODNAME
# ABSTRACT: NTP synchronisation status of a Palo Alto firewall

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=cut

sub _new {
    my $class = shift;
    my ($api_response) = @_;
    my %api_result = %{$api_response->{result}};
    my %ntp;

    # Check to see if NTP is responsive. If not return the error string passed.
    # This is yet another horrible API response from the PA
    if ($api_result{member} and !ref $api_result{member}) {
        return ERROR("NTP error: $api_result{member}");
    }

    $ntp{synched} = delete $api_result{synched} eq 'LOCAL' ? "" : 1;
    $ntp{servers} = [ $api_result{'ntp-server-1'}, $api_result{'ntp-server-2'} ];

    return bless \%ntp, $class;
}


=head2 synched

Returns true if the firewall is synchronised with an NTP server, false otherwise.

=cut

sub synched { return $_[0]->{synched} }


1;

