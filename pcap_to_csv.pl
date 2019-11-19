#!/usr/bin/env perl

use strict;
use warnings;
use 5.010;
use Getopt::Long;
use Pod::Usage;
use Carp;

use IPC::Cmd qw(can_run run);
use Text::CSV qw( csv );

=head1 NAME

blah.pl - A script that does something

=head1 SYNOPSIS

./blah.pl [options] file

=head2 OPTIONS

=over 4

=item B<-o|--option> - 

=back

=head1 DESCRIPTION

B<blah.pl> will do something

=cut

my %args;

GetOptions(\%args,
    "option=s",
    "help" => sub { pod2usage(1) }
) or pod2usage(2);

# Run a tshark report
can_run('tshark') or croak "Can't run tshark";
my ($success, $err, $buffer, $stdout, $stderr) = run(
    command => ['tshark', '-G', ''],
    verbose => 0,
    timeout => 20
);

my @field_report = split("\n", join('', @{ $buffer }));

my @dissector_names;
foreach (@field_report) {
    my $dissector = (split("\t", $_))[2];

    next if $dissector =~ m{^(http\.file_data)};
    next unless $dissector =~ m{^(frame|ethernet|arp|icmp|ip|udp|tcp|ssl|http)\.};

    push @dissector_names, $dissector;
}


my $export_command = [
    'tshark', '-r', $ARGV[0], 
    '-E', 'header=y', '-E', "separator=|", '-E', 'occurrence=f', '-E', 'quote=n',
    '-T', 'fields',
    map { ('-e', $_) } @dissector_names
];

#say STDERR "Command: " . join ' ', @{ $export_command };

($success, $err, $buffer, $stdout, $stderr) = run(
    command => $export_command,
    verbose => 0,
    timeout => 20
);

my $packet_dissection = join '', @{$buffer};

csv(
    out => 'out.csv',
    in => csv({
            in => \$packet_dissection,
            sep_char => "|",
            quote_char => '',
            headers => 'auto'
        })
);
