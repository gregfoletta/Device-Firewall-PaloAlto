package Device::Firewall::PaloAlto::Op::GlobalCounter;

use strict;
use warnings;
use 5.010;

use parent qw(Device::Firewall::PaloAlto::JSON);

# VERSION
# PODNAME
# ABSTRACT: Palo Alto firewall global system counter

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=cut

sub _new {
    my $class = shift;
    my ($counter_r) = @_;
    my %counter = %{$counter_r};

    # Change the rate and value to integers
    $counter{$_} += 0 foreach qw(rate value);

    return bless \%counter, $class;
}


=head1 METHODS

=head2 name

Returns the name of the counter.

=head2 rate

Returns the current rate at which the counter is increasing

=head2 value

The current value of the counter.

=cut

sub name { return $_[0]->{name} }
sub rate { return $_[0]->{rate} }
sub value { return $_[0]->{value} }


1;

