#!/usr/bin/env perl

use strict;
use warnings;
use 5.010;
use Getopt::Long;
use Pod::Usage;
use Carp;

use IPC::Cmd qw(can_run run);
use JSON;
use Text::Table;
use Hash::Fold qw(flatten);
use Text::CSV qw(csv);

=head1 NAME

pcap_to_csv.pl - Convert a PCAP file to a CSV file.

=head1 SYNOPSIS

./pcap_to_csv.pl [-rp] <file.pcap>

=head2 OPTIONS

=over 4

=item B<-r|--regex> 

=item B<-p|--print-fields> 

=back

=head1 DESCRIPTION

B<pcap_to_csv.pl> converts a PCAP file to a CSV. It wraps around tshark.

=cut

{
    my %args;

    GetOptions(\%args,
        "regex=s",
        "print-fields",
        "help" => sub { pod2usage(1) }
    ) or pod2usage(2);
    
    
    main(%args);
}


sub main {
    my %args = @_;
    my ($pcap_filename) = @ARGV;

    say "Gathering dissectors...";
    my @dissectors = dissectors($args{regex});

    # If the --print-fields|-p option is used, we print a table of the 
    # dissectors selected with their names, then exit
    if ($args{'print-fields'}) {
        my $table = Text::Table->new("Abbreviation", "Name");
        $table->load( map { [ $_->{abbrev}, $_->{name} ] } @dissectors );
        print $table;
        exit(2);
    }

    say "Extracting packets...";
    my $packet_dissection = tshark_json($pcap_filename, @dissectors);

    # Decode the JSON
    say "Decoding JSON...";
    my $json_packets = JSON->new->decode($packet_dissection) or die "Could not decode JSON\n";

    my %column_headings;
    my @packet_rows;
    say "Flattening packets...";

    @packet_rows = map { flatten($_->{_source}{layers}) } @{ $json_packets };

    say "Creating $pcap_filename.csv";
    csv(
        in => \@packet_rows, 
        out => "$pcap_filename.csv"
    );

}



sub dissectors {
    my ($regex) = @_;
    $regex //= qr(^(frame|eth|ip|arp|tcp|udp|icmp|dns|ssl|http|smb)\.);

    # Check if tshark is available
    can_run('tshark') or die "Can't run tshark - is it installed?\n";

    # Run the tshark 'fields' report
    my ($success, $err, $buffer, $stdout, $stderr) = run(
        command => ['tshark', '-G', ''],
        verbose => 0,
        timeout => 20
    );

    die "tshark -G command failed to run correctly: ".join('', @{$stderr})."\n" unless $success;

    # Join the buffer together
    my @field_report = split("\n", join('', @{ $buffer }));
   
    # Extract the relevant dissectors
    my @dissectors;
    foreach (@field_report) {
        my %dissector;
        @dissector{ qw(type name abbrev ftenum parent base bitmask blurb) } = split "\t";

        # We only want fields ('F'), not parents ('P')
        next unless $dissector{type} eq 'F';

        # Some blurbs are undefined
        $dissector{blurb} //= '';

        next unless $dissector{abbrev} =~ m{$regex};
    
        push @dissectors, \%dissector;
    }

    return @dissectors;
}




sub tshark_json {
    my ($pcap_filename, @dissectors) = @_;

    my $export_command = [
        'tshark', '-r', $pcap_filename, 
        '-T', 'json',
        map { ('-e', $_->{abbrev}) } @dissectors
    ];

    #say STDERR "Command: ".join(' ', @{$export_command});

    my ($success, $err, $buffer, $stdout, $stderr) = run(
        command => $export_command,
        verbose => 0,
        timeout => 20
    );

    die "Could not extract packets: ".join(' ',@{$stderr}) unless $success;

    return join '', @{$stdout};
}
