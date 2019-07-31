package Device::Firewall::PaloAlto::Op::Interfaces;

use strict;
use warnings;
use 5.010;

use Device::Firewall::PaloAlto::Op::Interface;
use Device::Firewall::PaloAlto::Errors qw(fatal_error);

use parent qw(Device::Firewall::PaloAlto::JSON);

use List::Util qw(first);
use Class::Error;

# VERSION
# PODNAME
# ABSTRACT: new module

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ERRORS 

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($api_return) = @_;
    my %interfaces;

    # Go through both the HW and IFNET interfaces and merge the keys.
    # We also fix up some of the cruft that comes through.
    for my $interface ( @{$api_return->{result}{ifnet}{entry}}, @{$api_return->{result}{hw}{entry}} ) {
        my $name = $interface->{name};
        @{ $interfaces{$name} }{ keys %{$interface} } = values %{$interface}; 

        # No IP address becomes an empty string.
        $interfaces{$name}{ip} = '' if !defined $interfaces{$name}{ip} or $interfaces{$name}{ip} eq 'N/A';
        # No virtual system becomes vsys ID 0
        $interfaces{$name}{vsys} //= '0';
    }

    # There are some logical interfaces where certain pieces of information is part of the parent.
    # For example a sub-interface doesn't have state, its state is inherited from the parent interface.
    for my $interface_name (keys %interfaces) {

        my ($child, $parent) = grep { defined $_ } ($interface_name) =~ m{
            ((ethernet\d+/\d+)\.\d+)|
            ((vlan)\.\d+)|
            ((tunnel)\.\d+)|
            ((loopback)\.\d+) |
            ((ae\d+)\.\d+)
        }xms;

        next unless defined $child;

        # Copy the keys we need across
        my @inherited_keys = qw(state);
        @{$interfaces{$child}}{@inherited_keys} = @{ $interfaces{$parent} }{@inherited_keys};

    }


    return bless \%interfaces, $class;
}

=head2 interface 

    $op->interfaces->interface('ethernet1/1');

Returns a L<Device::Firewall::PaloAlto::Op::Interface> object which matches the provided.

=cut

sub interface { 
    my ($self, $name) = @_;

    return fatal_error("No such interface '$name'") unless defined $self->{$name};

    return Device::Firewall::PaloAlto::Op::Interface->_new($self->{$name});
}


=head2 to_array

Returns an array of L<Device::Firewall::PaloAlto::Op::Interface> objects over which you can iterate. These are 
ordered by their internal id. 

=cut

sub to_array { 
    my $self = shift;

    my @interfaces = 
        map { Device::Firewall::PaloAlto::Op::Interface->_new($_) } 
        sort { $a->{id} <=> $b->{id} }
        values %{$self};

    return @interfaces;
}


1;

