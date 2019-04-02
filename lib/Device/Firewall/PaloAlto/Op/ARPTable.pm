package Device::Firewall::PaloAlto::Op::ARPTable;

use strict;
use warnings;
use 5.010;

use parent qw(Device::Firewall::PaloAlto::JSON);

use Device::Firewall::PaloAlto::Op::ARPEntry;

# VERSION
# PODNAME
# ABSTRACT: Palo Alto firewall ARP table

=encoding utf8

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 ERRORS 

=head1 METHODS

=cut

sub _new {
    my $class = shift;
    my ($api_return) = @_;
    my %arp_table;

    # Copy across the maximum and total enties in the table
    @arp_table{qw(max_entries total_entries)} = @{$api_return->{result}}{qw(max total)};

    my @entries = @{$api_return->{result}{entries}{entry}};

    # The ARP table is keyed on the IP address.
    $arp_table{entries} = { map { $_->{ip} => Device::Firewall::PaloAlto::Op::ARPEntry->_new($_) } @entries };

    return bless \%arp_table, $class;
}

=head2 entry 

Takes an IP address and returns a L<Device::Firewall::PaloAlto::Op::ARPEntry> object representing the ARP entry. 

If the ARP entry doesn't exist, it returns a L<Class::Error> object.

=cut

sub entry {
    my $self = shift;
    my ($ip) = @_;
    my $entry = $self->{entries}{$ip};

    return $entry ? $entry : Class::Error->new('ARP entry not found', 0);
}


=head2 current_entries

    say "Current ARP entries: ". $fw->op->arp_table->current_entries;

Returns the current number of entries in the ARP table. 

=cut
sub current_entries { return $_[0]->{total_entries} + 0 }

=head2 max_entries 

    say "Current ARP entries: ". $fw->op->arp_table->max_entries;

Returns the maximum number of entries supported on the firewall.

=cut 

sub max_entries { return $_[0]->{max_entries} + 0 }

=head2 to_array

Returns an array of L<Device::Firewall::PaloAlto::Op::ARPEntry> objects that represent the entries in the ARP table.

Returns undef if there are no entries in the table.

=cut

sub to_array {
    my $self = shift;

    return values %{ $self->{entries} };
}


1;

