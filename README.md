# NAME

Device::Firewall::PaloAlto - Interact with the Palo Alto firewall API

# VERSION

version 0.1.9

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

    # Can use the 'Test' module to test aspects of the firewall.
    # Returns true if both IPs are in the ARP table
    ok( $fw->test->arp( qw(192.0.2.1 192.0.2.2) );
    
    my $flow = $fw->test->secpolicy(
       from => 'Trust', to => 'Untrust',
       src => '192.0.2.1', dst => '203.0.113.1',
       protocol => 6, port => 443
    );

    ok( $flow, 'Flow was allowed' );
    say "Flow hit rule: ".$flow->rulename;

    # Add and remove user ID information on the firewall
    $fw->user_id->add_ip_mapping('192.0.2.1', 'localdomain\greg.foletta');

    # If the module is used in a one liner, fw() sub is exported to make
    # it easier to use, and to_json() automatically prints to STDOUT.
    bash% perl -MDevice::Firewall::PaloAlto -E 'fw()->op->arp_table->to_json'

# DESCRIPTION

This module provides an interface to the Palo Alto firewall API.

# FUNCTIONS 

## fw()

This is exported automatically into the main:: namespace if the module is
loaded within a one-liner - i.e. the calling script name is '-e'. If the module is
loaded within a normal script, this sub is not exported into main (though is of course accessible
using `Device::Firewall::PaloAlto::fw()`.)

The purpose of this sub is to reduce the amount of code needed in one liners. As an example

    # Long way
    % perl -MDevice::Firewall::PaloAlto -E 'Device::Firewall::PaloAlto::new(vefify_hostname => 0)->auth->op->system_info->to_json'
    
    # Shorter way
    % perl -MDevice::Firewall::PaloAlto -E 'fw()->op->system_info->to_json'

The sub takes `($user, $pass, $verify)` arguments. If `$user` and `$pass` arguments are not specified,
their undefinedness is passed through to `new()` and either environment variables are used or they default
to 'admin'. 

If `$verify` is not specified, `new()` is called with `verify_hostname =` 0>, and thus the TLS certificate is
not verified. This is opposite to the default behaviour of `new()` where the verification is performed.

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

## debug

    $fw->debug->op->interfaces();

Enables the debugging of HTTP requests and responses to the firewall.

## undebug 

Disables debugging.

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

Provides access to the [Device::Firewall::PaloAlto::UserID](https://metacpan.org/pod/Device::Firewall::PaloAlto::UserID) module. This module contains subroutines to add and remove dynamic IP to user mappings:

    # Add a mapping
    $fw->user_id->add_ip_mapping('192.0.2.1', 'localdomain\greg.foletta');

    # Remove a mapping
    $fw->user_id->rm_ip_mapping('192.0.2.1', 'localdomain\greg.foletta');

Refer to the module documentation for more information.

## test

Provides access to the [Device::Firewall::PaloAlto::Test](https://metacpan.org/pod/Device::Firewall::PaloAlto::Test) module. This module allows you to test the current state of a firewall.

    use Test::More;
    $test = $fw->test;
    ok( $test->interfaces('ethernet1/1', 'ethernet1/2'), 'Interfaces up' );

# ERRORS

Errors are handled differently depending on whether the script is running from a file, or from a 'one-liner'.

## File Errors

In the event of an error, a [Class::Error](https://metacpan.org/pod/Class::Error) object is returned. The module's documentation provides the best information, but essentially it slurps up any method calls, evaluates to false in a boolean context, and contains an error string and code.

This allows you to chain together method calls and the error is propagated all the way through. A suggested way of checking for errors would be:

    my $state = $fw->auth->op->interfaces->interface('ethernet1/1')->state or die $state->error();

## One-liner Errors

If the code is being run from a one-liner, the error is immeidately croaked rather than being returned as a [Class::Error](https://metacpan.org/pod/Class::Error) object. This saves the user from having to add the explicit croak at the end of the call on what it likely an already crowded shell line. An example:

    bash% perl -MDevice::Firewall::PaloAlto -E 'fw()->op->system_info->to_json'         
    HTTP Error: 500 Can't connect to pa.localdomain:443 (certificate verify failed) - 500 at -e line 1.

# ENVIRONMENT VARIABLES

The module uses the environment variables `PA_FW_URI`, `PA_FW_USERNAME` and `PA_FW_PASSWORD`. These map to the `uri`, `username` and `password` arguments to the new constructor. If any of these arguments are not present, the environment variable (if defined) is used.

The purpose of these is to reduce the clutter when using the module in a one-liner:

    bash% export PA_FW_URI=https://pa.localdomain
    bash% export PA_FW_USERNAME=greg.foletta
    bash% export PA_FW_PASSWORD=a_complex_password
    bash% perl -MDevice::Firewall::PaloAlto -E 'say fw()->op->interfaces->to_json'

# JSON

Most objects inherit the `to_json` method which returns a JSON representation of the object. By default the JSON is printed to STDOUT, however
a filename can be pased instead.

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
