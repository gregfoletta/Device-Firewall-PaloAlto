package Device::Firewall::PaloAlto::API;

use strict;
use warnings;
use 5.010;

use URI;
use Carp;
use LWP::UserAgent;
use HTTP::Request::Common;
use XML::Twig;
use Class::Error;

use Device::Firewall::PaloAlto::Errors qw(ERROR);

# VERSION
# PODNAME
# ABSTRACT: Palo Alto firewall API module

=encoding utf8

=head1 DESCRIPTION

This module contains API related methods used by the L<Device::Firewall::PaloAlto> package.

=cut 

# Sends a request to the firewall. The query string parameters come from the key/value 
# parameters passed to the function, ie _send_request(type = 'op', cmd => '<xml>')
#
# The method automatically adds in the autentication key if it exists.
sub _send_request {
    my $self = shift;
    my %query = @_;

    # If we're authenticated, add the API key
    $query{key} = $self->{api_key} if $self->{api_key};

    # Create the request and pass it to the raw request function.
    # This function exists to allow us to wrap it in debug functions
    # and see the raw requests and responses
    my $request = POST $self->{uri}->as_string, [ %query ];
    my $response = $self->_send_raw_request($request);
    
    # Check and return
    return _parse_and_check_response( $response );
}


sub _send_raw_request {
    my $self = shift;
    return $self->{user_agent}->request($_[0]);
}


sub _parse_and_check_response {
    my ($http_response) = @_;
    my $r;
    $r = _check_http_response($http_response) or return $r;
    return _check_api_response($r);
}
  
# Checks whether the HTTP response is an error. Carps and returns undef if it is.
# Returns the decoded HTTP content on success.
# On failure returns 'false'.
sub _check_http_response {
    my ($http_response) = @_;

    if ($http_response->is_error) {
        my $err = "HTTP Error: @{[$http_response->status_line]} - @{[$http_response->code]}";
        return ERROR($err, 0);
    }

    return $http_response->decoded_content;
}


# Parses the API response and checks if it's an API error.
# Returns a data structure representing the XML content on success.
# On failure returns 'false'.
sub _check_api_response {
    my ($http_content) = @_;
    return $http_content unless $http_content;

    my $api_response = XML::Twig->new->safe_parse( $http_content );
    return ERROR('Invalid XML returned in PA response') unless $api_response;

    $api_response = $api_response->simplify( forcearray => ['entry'] );

    if ($api_response->{status} eq 'error') {
        my $error_string = _clean_error_message($api_response);
        my $err = "API Error: $error_string  (Code: $api_response->{code})";
        return ERROR($err);
    }

    return $api_response;
}

# The error messages that come back from the firewall are in some very strange and different structures.
# This functiona attempts to clean them up
sub _clean_error_message {
    my ($response) = @_;
    my $ret_string;

    if (!defined $response->{msg}{line}) {
        return 'No error message defined';
    }

    my $error_structure = ref $response->{msg}{line};


    if (!$error_structure) {
        return $response->{msg}{line};
    } elsif ($error_structure eq 'ARRAY') {
        say 'ere';
        return join(', ', @{$response->{msg}{line}});
    } else {
        return '';
    }

    return $response->{msg}{line};
}


use Data::Dumper;

sub _debug_pre_wrap {
    my $self = shift;
    my ($http_request) = @_;
    say "REQUEST:";
    say $http_request->as_string;
}

sub _debug_post_wrap {
    my $self = shift;
    my ($http_response) = @_;
    say "RESPONSE:";
    say $http_response->as_string;
}



1;

