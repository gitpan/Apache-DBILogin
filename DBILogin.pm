# $Id: DBILogin.pm,v 1.6 2000/02/07 21:15:48 jdg117 Exp $
package Apache::DBILogin;
use strict;
use Apache();
use Apache::Constants qw(OK SERVER_ERROR AUTH_REQUIRED);
use DBI;
use vars qw($VERSION);

$VERSION = '1.6';
my(%Config) = (
    'Auth_DBI_data_source' => '',
    'Auth_DBI_authz_command' => '',
);
my $prefix = "Apache::DBILogin";

sub handler {
    my($r) = @_;
    my($key,$val);
    my $attr = {
        DBType => 'SQL',
    };
    while(($key,$val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^Auth_DBI_//;
        $attr->{$key} = $val;
    }
    
    return OK unless $r->is_initial_req;
    return check($r, $attr);
}
 
sub check {
    my($r, $attr) = @_;
    my($res, $sent_pwd);
 
    ($res, $sent_pwd) = $r->get_basic_auth_pw;
    return $res if $res; #decline if not Basic

    my $user = $r->connection->user;

    unless ( $attr->{data_source} ) {
        $r->log_reason("$prefix is missing the source parameter for database connect", $r->uri);
        return SERVER_ERROR;
    }

    my $dbh = DBI->connect($attr->{data_source}, $user, $sent_pwd, { PrintError=>0, RaiseError=>0 });
    unless( defined $dbh ) {
        $r->log_reason("user $user: $DBI::errstr", $r->uri);
        $r->note_basic_auth_failure;
        return AUTH_REQUIRED;
    }

    if ( $attr->{authz_command} ) {
        unless( defined ($dbh->do($attr->{authz_command})) ) {
            $r->log_reason("user $user: $DBI::errstr", $r->uri);
            $r->note_basic_auth_failure;
            return AUTH_REQUIRED;
        }
    }
           
    $dbh->disconnect;
    $r->header_in('Modperl_Password',$sent_pwd); # deprecated
    $r->header_in('Modperl_DBILogin_Password',$sent_pwd);
    $r->header_in('Modperl_DBILogin_data_source',$attr->{data_source});
    return OK;
}
1;
 
__END__

=head1 NAME

Apache::DBILogin - authenticates via a DBI connection

=head1 SYNOPSIS

See the access.conf file and the documentation for Apache::AuthenDBI

 #in .htaccess
 AuthName MyAuth
 AuthType Basic
 PerlHandler Apache::Registry::handler
 PerlAuthenHandler Apache::DBILogin::handler
 AddHandler perl-script pl
 
 PerlSetVar Auth_DBI_data_source dbi:Oracle:SQLNetAlias
 #PerlSetVar Auth_DBI_authz_command "SET ROLE DBA"
 
 Options Indexes FollowSymLinks ExecCGI
 AllowOverride All
  
 allow from all
 require valid-user
 satisfy all

=head1 DESCRIPTION

Apache::DBILogin allows authentication against a multi-user database. It is
intended to facilitate web-based transactions against a database server
as a particular database user. If you wish authenticate against a passwd
table instead, please see Edmund Mergl's Apache::AuthenDBI module.

Auth_DBI_authz_command is an optional valid database command, executed via
the DBI do method. In the above example I take advantage of Oracle roles, a
set of priviledges which can be assigned to groups of users.

=head1 ENVIRONMENT

Applications may access the clear text password as well as the data_source
via the environment variables B<HTTP_MODPERL_DBILOGIN_PASSWORD> and
B<HTTP_MODPERL_DBILOGIN_DATA_SOURCE>. B<HTTP_MODPERL_PASSWORD> is deprecated.

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

=head1 SEE ALSO

mod_perl(1), Apache::DBI(3), Apache::AuthenDBI(3), and Apache::AuthzDBI(3)

=head1 AUTHOR

John Groenveld E<lt>groenveld@acm.orgE<gt>

=cut
