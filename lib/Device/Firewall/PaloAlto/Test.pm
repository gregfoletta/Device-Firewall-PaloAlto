package Device::Firewall::PaloAlto::Test;


use strict;
use warnings;
use 5.010;

# VERSION
# PODNAME
# ABSTRACT: Test module for Palo Alto firewalls

=encoding utf8

=head1 SYNOPSIS

    use Test::More;
    my $test = Device::Firewall::PaloAlto->new(username => 'admin', password => 'admin')->auth->test;
    ok( $test->interfaces(['ethernet1/1', 'ethernet1/2']), 'Interfaces are up' );

=head1 DESCRIPTION

This module holds methods that perform tests on the current state of the firewall.

=head1 METHODS

=head2 new

The C<new()> method can be used, but in general it's easier to call the C<test()> method from the L<Device::Firewall::PaloAlto> module.

    # Can use it in this manner
    my $fw = Device::Firewall::PaloAlto->new(username => 'admin', password => 'admin');
    $fw->auth or croak "Could not authenticate to the firewall";
    my $test = Device::Firewall::PaloAlto::Test->new($fw);

    # Generally better to use it in this manner
    my $test = Device::Firewall::PaloAlto->new(username => 'admin', password => 'admin')->auth->test or croak "Could not create test module";

=cut

sub new {
    my $class = shift;
    my ($fw) = @_;

    return bless { fw => $fw }, $class;
}

=head2 interfaces

Takes a list of interface names and returns true if all interfaces are up, or false if any interfaces are down.

Returns false if the operation to retreive the interfaces fails.
    
    ok( $fw->test->interfaces('ethernet1/1'), 'Internet interface' );

=cut

sub interfaces {
    my $self = shift;
    my (@test_interfaces) = @_;

    my $interfaces = $self->{fw}->op->interfaces or return;

    for my $test_int (@test_interfaces) {
        my $real_int = $interfaces->interface($test_int);

        return unless $real_int and $real_int->state eq 'up';
    }

    return 1;
}


=head2 arp

Takes a list of IP address and returns true if all of them have entries in the ARP table. Returns false if any IP does not have and entry.

ARP entries are considered valid if their state is 'static' or 'complete'.

=cut

sub arp {
    my $self = shift;
    my (@test_arp_entries) = @_;

    my $arp_entries = $self->{fw}->op->arp_table;

    for my $test_arp (@test_arp_entries) {
        my $real_arp = $arp_entries->entry($test_arp);
        return unless $real_arp and ($real_arp->status eq 'static' or $real_arp->status eq 'complete');
    }

    return 1;
}



1;

