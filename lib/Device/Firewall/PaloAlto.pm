package Device::Firewall::PaloAlto;

use strict;
use warnings;
use 5.010;

use parent 'Device::Firewall::PaloAlto::API';

use Device::Firewall::PaloAlto::Op;
use Device::Firewall::PaloAlto::UserID;

# VERSION
# PODNAME
# ABSTRACT: Interact with the Palo Alto firwall API

=encoding utf8

=head1 SYNOPSIS

    use Device::Firewall::PaloAlto;

    # Constructon doesn't initiate any comms with the firewall.    
    my $fw = Device::Firewall::PaloAlto->new(
        uri => 'https://pa.localdomain',
        username => 'user11',
        password => 'a_password'
    );

    # Auth is required before performing any actions
    $fw->auth or die "Could not authenticate";

    # Calls can be chained together
    my $proto = $fw
        ->op
        ->virtual_router('default')
        ->route('0.0.0.0/0)
        ->protocol

    # Collection objects (interfaces, virtual router, etc) can be 
    # directly converted to an array of objects.
    say $_->name foreach $fw->op->interfaces->to_array;

=head1 DESCRIPTION

This module provides an interface to the Palo Alto firewall API.

=head1 DETAILS


=head1 METHODS

=head2 new

    my $fw = Device::Firewall::PaloAlto(
        uri => 'https://pa.localdomain',
        username => 'user',
        password => 'pass',
        verify_hostname => 1
    );

The C<new()> method creates a new Device::Firewall::PaloAlto object. The uri, username and password can be
passed in using the environment variables 'PA_FW_URI', PA_FW_USERNAME and PA_FW_PASSWORD. If no environment
variables are set, the username and password both default to 'admin'.

=cut

=head2 auth

    my $fw = $fw->auth;

This function authenticates the credentials passed to new against the firewall.

If successful, it returns the object itself to all method calls to be chains. If unsuccessful, it returns a L<Class::Error> object.

=head2 vsys

Sets the virtual system (vsys) ID to which calls will be applied. By default vsys 1 is used.

=cut

sub vsys {
    my $self = shift;
    ($self->{vsys_id}) = @_;
}


=head2 op

Returns a L<Device::Firewall::PaloAlto::Op> object. This object has methods to perform operational tasks on the firewall.

    my $fw_op = $fw->auth->op();
   
    # Return the firewall's interfaces
    my $interfaces = $fw_op->interfaces();

    # Return the ARP table
    my $arp_table = $fw->op->arp_table();

    # Returns the routes in the guest_vr virtual router
    my $routes = $fw->op->virtual_router('guest_vr');

=cut

sub op {
    my $self = shift;

    return Device::Firewall::PaloAlto::Op->new($self);
}

=head2 user_id


=cut

sub user_id {  
    my $self = shift;
    return Device::Firewall::PaloAlto::UserID->_new($self);
}

=head2 Errors

Errors are handled differently depending on whether the script is running from a file, or from a 'one-liner'.

=head3 File Errors

In the event of an error, a L<Class::Error> object is returned. The module's documentation provides the best information, but essentially it slurps up any method calls, evaluates to false in a boolean context, and contains an error string and code.

This allows you to chain together method calls and the error is propagated all the way through. A suggested way of checking for errors would be:

    my $state = $fw->auth->op->interfaces->interface('ethernet1/1')->state or die $state->error();

=head3 One-liner Errors

If the code is being run from a one-liner, the error is immeidately croaked rather than being returned as a L<Class::Error> object. This saves the user from having to add the explicit croak at the end of the call on what it likely an already crowded shell line. An example:

    bash# perl -MDevice::Firewall::PaloAlto -E 'Device::Firewall::PaloAlto->new->auth->op->system_info->to_json'         
    HTTP Error: 500 Can't connect to pa.localdomain:443 (certificate verify failed) - 500 at -e line 1.

=head2 Environment Variables

The module uses the environment variables C<PA_FW_URI>, C<PA_FW_USERNAME> and C<PA_FW_PASSWORD>. These map to the C<uri>, C<username> and C<password> arguments to the new constructor. If any of these arguments are not present, the environment variable (if defined) is used.

The purpose of these is to reduce the clutter when using the module in a one-liner:

    bash# export PA_FW_URI=https://pa.localdomain
    bash# export PA_FW_USERNAME=greg.foletta
    bash# export PA_FW_PASSWORD=a_complex_password
    bash# perl -IDevice::Firewall::PaloAlto -E 'say Device::Firewall::PaloAlto->new->auth->op->interfaces->to_json'

=head2 JSON

Almost all of the objects have a C<to_json> method which returns a JSON representation of the object. There are two ways to use this method:

    # Outputs the json to STDOUT
    $fw->op->system_info->to_json;

    # Outputs the json the file 'firewall_info.json' in the current working directory
    $fw->op->system_info->to_json('firewall_info.json');

=cut

1;
