# NAME

Device::Firewall::PaloAlto - Interact with the Palo Alto firwall API

# VERSION

version 0.1.4\_1

# SYNOPSIS

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

# DESCRIPTION

This module provides an interface to the Palo Alto firewall API.

# DETAILS

# METHODS

## new

    my $fw = Device::Firewall::PaloAlto(
        uri => 'https://pa.localdomain',
        username => 'user',
        password => 'pass',
        verify_hostname => 1
    );

The `new()` method creates a new Device::Firewall::PaloAlto object. The uri, username and password can be
passed in using the environment variables 'PA\_FW\_URI', PA\_FW\_USERNAME and PA\_FW\_PASSWORD. If no environment
variables are set, the username and password both default to 'admin'.

## auth

    my $fw = $fw->auth;

This function authenticates the credentials passed to new against the firewall.

If successful, it returns the object itself to all method calls to be chains. If unsuccessful, it returns a [Class::Error](https://metacpan.org/pod/Class::Error) object.

## vsys

Sets the virtual system (vsys) ID to which calls will be applied. By default vsys 1 is used.

## op

Returns a [Device::Firewall::PaloAlto::Op](https://metacpan.org/pod/Device::Firewall::PaloAlto::Op) object. This object has methods to perform operational tasks on the firewall.

     my $fw_op = $fw->auth->op();
    
     # Return the firewall's interfaces
     my $interfaces = $fw_op->interfaces();

     # Return the ARP table
     my $arp_table = $fw->op->arp_table();

     # Returns the routes in the guest_vr virtual router
     my $routes = $fw->op->virtual_router('guest_vr');

## user\_id

## Errors

Errors are handled differently depending on whether the script is running from a file, or from a 'one-liner'.

### File Errors

In the event of an error, a [Class::Error](https://metacpan.org/pod/Class::Error) object is returned. The module's documentation provides the best information, but essentially it slurps up any method calls, evaluates to false in a boolean context, and contains an error string and code.

This allows you to chain together method calls and the error is propagated all the way through. A suggested way of checking for errors would be:

    my $state = $fw->auth->op->interfaces->interface('ethernet1/1')->state or die $state->error();

### One-liner Errors

If the code is being run from a one-liner, the error is immeidately croaked rather than being returned as a [Class::Error](https://metacpan.org/pod/Class::Error) object. This saves the user from having to add the explicit croak at the end of the call on what it likely an already crowded shell line. An example:

    bash# perl -MDevice::Firewall::PaloAlto -E 'Device::Firewall::PaloAlto->new->auth->op->system_info->to_json'         
    HTTP Error: 500 Can't connect to pa.localdomain:443 (certificate verify failed) - 500 at -e line 1.

## Environment Variables

The module uses the environment variables `PA_FW_URI`, `PA_FW_USERNAME` and `PA_FW_PASSWORD`. These map to the `uri`, `username` and `password` arguments to the new constructor. If any of these arguments are not present, the environment variable (if defined) is used.

The purpose of these is to reduce the clutter when using the module in a one-liner:

    bash# export PA_FW_URI=https://pa.localdomain
    bash# export PA_FW_USERNAME=greg.foletta
    bash# export PA_FW_PASSWORD=a_complex_password
    bash# perl -IDevice::Firewall::PaloAlto -E 'say Device::Firewall::PaloAlto->new->auth->op->interfaces->to_json'

## JSON

Almost all of the objects have a `to_json` method which returns a JSON representation of the object. There are two ways to use this method:

    # Outputs the json to STDOUT
    $fw->op->system_info->to_json;

    # Outputs the json the file 'firewall_info.json' in the current working directory
    $fw->op->system_info->to_json('firewall_info.json');

# AUTHOR

Greg Foletta <greg@foletta.org>

# COPYRIGHT AND LICENSE

This software is copyright (c) 2019 by Greg Foletta.

This is free software; you can redistribute it and/or modify it under
the same terms as the Perl 5 programming language system itself.
