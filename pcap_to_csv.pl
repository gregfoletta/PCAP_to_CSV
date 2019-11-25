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

pcap_to_csv.pl - Convert a PCAP file to a CSV file.

=head1 SYNOPSIS

./pcap_to_csv.pl pcap_file

=head2 OPTIONS

=over 4

=item B<-o|--option> - 

=back

=head1 DESCRIPTION

B<pcap_to_csv.pl> converts a PCAP file to a CSV. It wraps around tshark.

=cut

my %args;

GetOptions(\%args,
    "help" => sub { pod2usage(1) }
) or pod2usage(2);


main(@ARGV);


sub main {
    my ($pcap_filename) = @_;

    my @dissector_names = dissector_names();

    my $packet_dissection = raw_tshark_csv($pcap_filename, @dissector_names);
    
    csv(
        out => "$pcap_filename.csv",
        in => csv({
                in => \$packet_dissection,
                sep_char => "|",
                quote_char => '',
                headers => 'auto'
            })
    );
}



sub dissector_names {
    # Check if tshark is available
    can_run('tshark') or croak "Can't run tshark";

    # Run the tshark 'fields' report
    my ($success, $err, $buffer, $stdout, $stderr) = run(
        command => ['tshark', '-G', ''],
        verbose => 0,
        timeout => 20
    );

    # Join the buffer together
    my @field_report = split("\n", join('', @{ $buffer }));
   
    # Extract the relevant dissectors
    my @dissector_names;
    foreach (@field_report) {
        my $dissector = (split("\t", $_))[2];
    
        next if $dissector =~ m{^(http\.file_data)};
        next unless $dissector =~ m{^(frame|ethernet|arp|icmp|ip|udp|tcp|ssl|http)\.};
    
        push @dissector_names, $dissector;
    }

    return sort @dissector_names;
}



sub raw_tshark_csv {
    my ($pcap_filename, @dissector_names) = @_;

    my $export_command = [
        'tshark', '-r', $pcap_filename, 
        '-E', 'header=y', '-E', "separator=|", '-E', 'occurrence=f', '-E', 'quote=n',
        '-T', 'fields',
        map { ('-e', $_) } @dissector_names
    ];
    
    my ($success, $err, $buffer, $stdout, $stderr) = run(
        command => $export_command,
        verbose => 0,
        timeout => 20
    );
    
    return join '', @{$buffer};
}

