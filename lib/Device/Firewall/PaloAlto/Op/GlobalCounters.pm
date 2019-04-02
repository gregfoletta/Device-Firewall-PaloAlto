package Device::Firewall::PaloAlto::Op::GlobalCounters;

use strict;
use warnings;
use 5.010;

use parent qw(Device::Firewall::PaloAlto::JSON);

use Device::Firewall::PaloAlto::Op::GlobalCounter;
use Device::Firewall::PaloAlto::Errors qw(ERROR);


# VERSION
# PODNAME
# ABSTRACT: Palo Alto firewall global system counters

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=cut

sub _new {
    my $class = shift;
    my ($api_return) = @_;

    my %counters = map { $_->{name} => Device::Firewall::PaloAlto::Op::GlobalCounter->_new($_) } @{$api_return->{result}{global}{counters}{entry}};

    return bless \%counters, $class;
}


=head2 

Returns a L<Device::Firewall::PaloAlto::Op::GlobalCounter> object based on the counter's name.

=cut

sub name { return defined $_[0]->{$_[1]} ? $_[0]->{$_[1]} : ERROR("No such counter name", 0)  }

=head2 to_array

Returns an array of L<Device::Firewall::PaloAlto::Op::GlobalCounter> objects representing the global counters.

=cut

sub to_array { return values %{$_[0]} }




1;

