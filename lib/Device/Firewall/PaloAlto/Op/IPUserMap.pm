package Device::Firewall::PaloAlto::Op::IPUserMap;

use strict;
use warnings;
use 5.010;

# VERSION
# PODNAME
# ABSTRACT: Palo Alto IP to user mapping entry.

use parent qw(Device::Firewall::PaloAlto::JSON);

=encoding utf8

=head1 SYNOPSIS
    
    my $mappings = $fw->op->ip_user_mapping;
    say $_->name foreach $mappings->to_array; 

=head1 DESCRIPTION

This object represents a single IP to user mapping.

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($api_response) = @_;
    my %userid_entry = %{$api_response};

    return bless \%userid_entry, $class;
}

=head2 ip

Returns the IP address of the IP to user mapping.

=head2 user

Returns the user of the IP to user mapping.

=cut

sub ip { return $_[0]->{ip} }
sub user { return $_[0]->{user} }
sub type { return $_[0]->{type} }
sub vsys { return $_[0]->{vsys} }


1;

