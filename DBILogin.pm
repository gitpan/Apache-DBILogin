# $Id: DBILogin.pm,v 1.2 2001/02/21 19:14:47 jdg117 Exp $
package Apache::DBILogin;
use strict;
use Apache();
use Apache::Constants qw(OK SERVER_ERROR AUTH_REQUIRED FORBIDDEN);
use DBI;
use vars qw($VERSION);

$VERSION = '2.0';
my(%Config) = (
    'Auth_DBI_data_source' => '',
    'Auth_DBI_authz_command' => '',
    'DBILogin_Oracle_authz_command' => '',
);
my $prefix = "Apache::DBILogin";

sub authen {
    my $r = shift @_;
    return OK unless $r->is_initial_req;

    my($key,$val);
    my $attr = {};
    while(($key,$val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^Auth_DBI_//;
        $attr->{$key} = $val;
    }
    
    return test_authen($r, $attr);
}
 
sub test_authen {
    my($r, $attr) = @_;
 
    my ($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if ( $res ); #decline if not Basic

    my $user = $r->connection->user;

    unless ( $attr->{data_source} ) {
        $r->log_reason("$prefix is missing the source parameter for database connect", $r->uri);
        return SERVER_ERROR;
    }

    my $dbh = DBI->connect($attr->{data_source}, $user, $sent_pwd, { AutoCommit=>0, RaiseError=>0 });
    unless( defined $dbh ) {
        $r->log_reason("user $user: $DBI::errstr", $r->uri);
        $r->note_basic_auth_failure;
        return AUTH_REQUIRED;
    }

    # to be removed in next version
    if ( $attr->{authz_command} ) {
        unless( defined ($dbh->do($attr->{authz_command})) ) {
            $r->log_reason("user $user: $DBI::errstr", $r->uri);
            $r->note_basic_auth_failure;
            return AUTH_REQUIRED;
        }
    }
           
    $dbh->disconnect;
    $r->header_in('Modperl_DBILogin_Password',$sent_pwd);
    $r->header_in('Modperl_DBILogin_data_source',$attr->{data_source});
    return OK;
}

sub authz {
    my $r = shift @_;
    return OK unless $r->is_initial_req;

    my $user = $r->connection->user;

    my($key,$val);
    my $attr = {};
    while(($key,$val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^Auth_DBI_//;
        $attr->{$key} = $val;
    }
    
    return test_authz($r, $attr);
}

sub test_authz {
    my($r, $attr) = @_;

    my ($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if ( $res ); #decline if not Basic

    my $user = $r->connection->user;

    unless ( $attr->{data_source} ) {
        $r->log_reason("$prefix is missing the source parameter for database connect", $r->uri);
        return SERVER_ERROR;
    }

    my $dbh = DBI->connect($attr->{data_source}, $user, $sent_pwd, {AutoCommit=>0, RaiseError=>0});
    unless( defined $dbh ) {
        $r->log_reason("user $user: $DBI::errstr", $r->uri);
        return SERVER_ERROR;
    }

    my $authz_result = FORBIDDEN;
    my $sth;
    foreach my $requirement ( @{$r->requires} ) {
        my $require = $requirement->{requirement};
        if ( $require eq "valid-user" ) {
            $authz_result = OK;
        } elsif ( $require =~ s/^user\s+// ) { 
                foreach my $valid_user (split /\s+/, $require) {
                    if ( $user eq $valid_user ) {
                        $authz_result = OK;
                        last;
                    }
                }
                if ( $authz_result != OK ) {
                    my $explaination = <<END;
<HTML>
<HEAD><TITLE>Unauthorized</TITLE></HEAD>
<BODY>
<H1>Unauthorized</H1>
User must be one of these required users: $require
</BODY>
</HTML>
END
                    $r->custom_response(FORBIDDEN, $explaination);
                    $r->log_reason("user $user: not authorized", $r->uri);
                }
            } elsif ( $require =~ s/^group\s+// ) {
                    foreach my $group (split /\s+/, $require) {
                        $authz_result = is_member($r, $dbh, $group);
                        last if ( $authz_result == OK );
                        if ( $authz_result == SERVER_ERROR ) {
                            $r->log_reason("user $user: $@", $r->uri);
                            return SERVER_ERROR;
                        }
                    }
                    if ( $authz_result == FORBIDDEN ) {
                        my $explaination = <<END;
<HTML>
<HEAD><TITLE>Unauthorized</TITLE></HEAD>
<BODY>
<H1>Unauthorized</H1>
User must be member of one of these required groups: $require
</BODY>
</HTML>
END
                        $r->custom_response(FORBIDDEN, $explaination);
                        $r->log_reason("user $user: not authorized", $r->uri);
                    }
                }
    }

    $dbh->disconnect;
    return $authz_result;
}

1;
 
__END__

=head1 NAME

Apache::DBILogin - authenticates and authorizes via a DBI connection

=head1 SYNOPSIS

 #in .htaccess
 AuthName MyAuth
 AuthType Basic
 PerlAuthenHandler Apache::DBILogin::authen
 PerlSetVar Auth_DBI_data_source dbi:Oracle:SQLNetAlias
 PerlAuthzHandler Apache::DBILogin::authz
 
 allow from all
 require group connect resource dba
 satisfy all

 #in startup.pl
 package Apache::DBILogin;
 
 # is_member function for authz handler
 #  expects a request object, database handle, and the group you which to test
 #  returns a valid response code
 sub is_member {
     my ($r, $dbh, $group) = @_;
 
     my $sth;
     eval {
         # no, Oracle doesn't support binding in SET ROLE statement
         $sth = $dbh->prepare("SET ROLE $group") or die $DBI::errstr;
     };
     return SERVER_ERROR if ( $@ );
        
     return ( defined $sth->execute() ) ? OK : FORBIDDEN;
 }

=head1 DESCRIPTION

Apache::DBILogin allows authentication and authorization against a
multi-user database.

It is intended to facilitate web-based transactions against a database server
as a particular database user. If you wish authenticate against a passwd
table instead, please see Edmund Mergl's Apache::AuthDBI module.

Group authorization is handled by your Apache::DBILogin::is_member()
function which you must define if you enable the authz handler.

The above example uses Oracle roles to assign group membership. A role is a
set of database privileges which can be assigned to users. Unfortunately,
roles are vendor specific. Under Oracle you can test membership with
"SET ROLE role_name" statement. You could also query the data dictionary,
DBA_ROLE_PRIVS, but under Oracle that requires explicit privilege.
Documentation patches for other databases are welcome.

=head1 ENVIRONMENT

Applications may access the clear text password as well as the data_source
via the environment variables B<HTTP_MODPERL_DBILOGIN_PASSWORD> and
B<HTTP_MODPERL_DBILOGIN_DATA_SOURCE>.

 #!/usr/bin/perl -wT
 
 use strict;
 use CGI;
 use DBI;
 my $name = $ENV{REMOTE_USER};
 my $password = $ENV{HTTP_DBILOGIN_PASSWORD};
 my $data_source = $ENV{HTTP_DBILOGIN_DATA_SOURCE};
 my $dbh = DBI->connect($data_source, $name, $password)
 	or die "$DBI::err: $DBI::errstr\n";
 ...

=head1 SECURITY

The database user's clear text passwd is made available in the
server's environment. Do you trust your developers?

=head1 BUGS

Probably lots, I'm not the best programmer in the world.

=head1 NOTES

Feel free to email me with comments, suggestions, flames. Its the
only way I'll become a better programmer.

=head1 SEE ALSO

mod_perl(1), Apache::DBI(3), and Apache::AuthDBI(3)

=head1 AUTHOR

John Groenveld E<lt>groenveld@acm.orgE<gt>

=cut
