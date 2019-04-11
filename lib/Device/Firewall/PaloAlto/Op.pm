package Device::Firewall::PaloAlto::Op;


use strict;
use warnings;
use 5.010;

use Device::Firewall::PaloAlto::Op::SysInfo;
use Device::Firewall::PaloAlto::Op::Interfaces;
use Device::Firewall::PaloAlto::Op::ARPTable;
use Device::Firewall::PaloAlto::Op::VirtualRouter;
use Device::Firewall::PaloAlto::Op::Tunnels;
use Device::Firewall::PaloAlto::Op::GlobalCounters;
use Device::Firewall::PaloAlto::Op::IPUserMaps;

use XML::LibXML;


# VERSION
# PODNAME
# ABSTRACT: Operations module for Palo Alto firewalls

=encoding utf8

=head1 SYNOPSIS

    my $op = Device::Firewall::PaloAlto->new(username => 'admin', password => 'admin')->auth->op;
    my @interfaces = $op->interface->to_array;

=head1 DESCRIPTION

This module holds methods that perform operation commands on the firewall.

=head1 METHODS

=head2 new

The C<new()> method can be used, but in general it's easier to call the C<op()> method from the L<Device::Firewall::PaloAlto> module.

=cut

sub new {
    my $class = shift;
    my ($fw) = @_;

    return bless { fw => $fw }, $class;
}

=head2 vsys

Sets the virtual system (vsys) ID to which calls will be applied. By default vsys 1 is used.

On success reutrns the Device::Firewall::PaloAlto::Op object so calls can be chained together. On failure it returns a L<Class::Error> object.

=cut

sub vsys {
    my $self = shift;
    my ($vsys_id) = @_;

    my $vsys_string = "vsys$vsys_id";
    my $r = $self->_send_op_cmd('set system setting target-vsys', $vsys_string);

    if ($r) {
        $self->{fw}{active_vsys_id} = $vsys_id;
        return $self;
    } else {
        return $r;
    }
}

=head2 system_info

    my $info = $fw->op->system_info;

Returns a L<Device::Firewall::PaloAlto::Op::SysInfo> object containing system information about the firewall.

=cut

sub system_info {
    my $self = shift;

    return Device::Firewall::PaloAlto::Op::SysInfo->_new( $self->_send_op_cmd('show system info') );
}


=head2 interfaces

    my $interfaces = $fw->op->interfaces();

Returns a L<Device::Firewall::PaloAlto::Op::Interfaces> object containing all of the interfaces, both physical and logical, on the device.

=cut

sub interfaces {
    my $self = shift;

    return Device::Firewall::PaloAlto::Op::Interfaces->_new( $self->_send_op_cmd('show interface', 'all') );
}

=head2 arp_table

    my $arp = $fw->op->arp_table();

Returns a L<Device::Firewall::PaloAlto::Op::ARPTable> object representing all of the ARP entries on the device.

=cut


sub arp_table {
    my $self = shift;

    return Device::Firewall::PaloAlto::Op::ARPTable->_new( $self->_send_op_cmd('show arp', { name => 'all' }) );
}

=head2 virtual_router

    # If no virtual router specified, returns the one named 'default'
    my $routing_tables = $fw->op_routing_tables();

    # Retrieve thee 'guest_vr' virtual router
    my $vr = $fw->op->virtual_router('guest_vr');

Returns a L<Device::Firewall::PaloAlto::Op::VirtualRouter> object representing all of the routing tables on the firewall.

=cut


sub virtual_router {
    my $self = shift;
    my ($table_name) = @_;
    $table_name //= 'default';

    return Device::Firewall::PaloAlto::Op::VirtualRouter->_new( $self->_send_op_cmd('show routing route virtual-router', $table_name) );
}

=head2 tunnels

Returns a L<Device::Firewall::PaloAlto::Op::Tunnels> object representing the current active IPSEC tunnels.

    my $tunnels = $fw->op->tunnels
    my $client_site = $tunnels->gw('remote_site_gw');

=cut

sub tunnels {
    my $self = shift;

    return Device::Firewall::PaloAlto::Op::Tunnels->_new( 
        $self->_send_op_cmd('show vpn ike-sa'),
        $self->_send_op_cmd('show vpn ipsec-sa') 
    );
}

=head2 global_counters

Returns a L<Device::Firewall::PaloAlto::Op::GlobalCounters> object representing the global counters.

    # Extract out the drop alerts alerts
    my $counters = $fw->op->global_counters;
    my @drop_counter = grep { $_->severity eq 'drop' } $counters->to_array;

=cut

sub global_counters {
    my $self = shift;
    my %args = @_;

    $args{delta} //= 0;
    my @cmd = $args{delta} ? 
        ('show counter global filter delta', 'yes') :
        ('show counter global');
    
    return Device::Firewall::PaloAlto::Op::GlobalCounters->_new(
        $self->_send_op_cmd(@cmd)
    );
}


=head2 ip_user_mapping

Returns a L<Device::Firewall::PaloAlto::Op::IPUserMaps> objects representing the current active IP to user mappings on the device.

    my $maps = $fw->op->ip_user_mapping;
    my @mappings = grep { $_->user eq 'greg.foleta' } $map->to_array;

=cut

sub ip_user_mapping {
    my $self = shift;

    return Device::Firewall::PaloAlto::Op::IPUserMaps->_new( $self->_send_op_cmd('show user ip-user-mapping all') );
}



sub _send_op_cmd {
    my $self = shift;
    my ($cmd, $var) = @_;

    return $self->{fw}->_send_request(type => 'op', cmd => _gen_op_xml($cmd, $var));
}



# Generates the proper XML RPC call to go in the operational 'cmd' field.
# The first value is the command, which is split on space and turned into XML, e.g.
# _gen_op_xml('show routing route') => <show><routing><route></route></routing></show>
#
# You can add a variable which becomes text in the last tag, e.g:
# _gen_op_xml('show interface', 'all') => <show><interface>all</interface></show>
# 
# You can add a lead node with an attribute using a hashref as the variable
# _gen_op_xml('show arp', { name => 'all' }) => <show><arp><entry name = 'all'/></arp></show>
#

sub _gen_op_xml {
    my ($command, $variable) = @_;
    my $xml_doc = XML::LibXML::Document->new(); 

    my @command_words = split / /, $command;
    $variable //= '';


    my $leaf;
    if (!ref $variable) {
        $leaf = $xml_doc->createTextNode($variable);
    } elsif (ref $variable eq 'HASH') {
        $leaf = $xml_doc->createElement('entry');
        $leaf->setAttribute(%{ $variable });
    }


    my $parent;
    for my $word (reverse @command_words) {
        # If the child is either the previous parent or the base text node (which could be an empty string)
        my $child = $parent // $leaf;
        $parent = $xml_doc->createElement($word);
        $parent->appendChild($child);
    }

    return $parent->toString;
}


1;

