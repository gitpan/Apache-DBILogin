#
# Check for non-standard modules that are used by this library.
# This code was stolen from Gisle Aas' LWP
#
$| = 1;
my $missing_modules = 0;

print "Checking for Apache::DBI......";
eval {
    require Apache::DBI;
};
if ($@) {
    print " failed\n";
    $missing_modules++;
    print <<EOT;
$@
The Apache::DBI module is needed maintain the DBI connection.
 
EOT
    sleep(2);  # Don't hurry too much
} else {
    print " ok\n";
}

print <<EOT if $missing_modules;
The missing modules can be obtained from CPAN.  Visit
<URL:http://www.perl.com/CPAN/> to find a CPAN site near you.

EOT

use ExtUtils::MakeMaker;

WriteMakefile(
   NAME          => 'Apache::DBILogin',
   DISTNAME      => 'Apache-DBILogin',
   VERSION_FROM  => 'DBILogin.pm',
);
