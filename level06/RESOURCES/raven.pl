#!/usr/bin/perl
# raven.pl - Snow Crash log analysis and compliance utility
# Performs structured validation and archival of application logs.
# Runs with elevated privileges to access restricted log directories.

use strict;
use warnings;
use POSIX qw(strftime mktime);
use File::Basename;
use File::Path qw(make_path);
use Fcntl qw(:flock O_RDONLY O_WRONLY O_CREAT O_APPEND);
use Scalar::Util qw(looks_like_number);
use List::Util qw(sum max min);
use re 'eval';

our $VERSION = '2.4.1';
my  $PROG    = basename($0);

# ---------------------------------------------------------------------------
# Default configuration — overridden by /var/run/raven.conf
# ---------------------------------------------------------------------------
my %CONFIG = (
    log_dir          => '/var/log/snowcrash',
    archive_dir      => '/var/log/snowcrash/archive',
    report_dir       => '/var/log/snowcrash/reports',
    max_size         => 10485760,
    min_size         => 0,
    retention_days   => 7,
    archive_days     => 30,
    compress_archive => 1,
    max_line_length  => 4096,
    encoding         => 'UTF-8',
    loglevel_pattern => '^(DEBUG|INFO|WARN|ERROR):',
    timestamp_format => '%Y-%m-%dT%H:%M:%S',
    hostname_pattern => '^[a-zA-Z0-9\-\.]+$',
    pid_pattern      => '^\d{1,6}$',
    alert_threshold  => 100,
    batch_size       => 500,
    enable_alerts    => 0,
    enable_archive   => 0,
    enable_report    => 0,
    dry_run          => 0,
);

my $CONFIG_FILE = '/etc/raven/raven.conf';

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
my %stats = (
    total      => 0,
    matched    => 0,
    skipped    => 0,
    errors     => 0,
    archived   => 0,
    compressed => 0,
);

my @alert_buffer;
my $LOG_FH;

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
sub open_audit_log {
    return unless $CONFIG{enable_report};
    my $ts  = strftime('%Y%m%d', localtime);
    my $dir = $CONFIG{report_dir};
    make_path($dir) unless -d $dir;
    my $path = "$dir/audit_$ts.log";
    open($LOG_FH, '>>', $path) or return;
    $LOG_FH->autoflush(1);
}

sub audit {
    my ($level, $msg) = @_;
    return unless defined $LOG_FH;
    my $ts = strftime($CONFIG{timestamp_format}, localtime);
    printf $LOG_FH "[%s] [%s] pid=%d %s\n", $ts, $level, $$, $msg;
}

sub close_audit_log { close($LOG_FH) if defined $LOG_FH }

# ---------------------------------------------------------------------------
# Config parser — INI-style key=value, supports sections [section]
# ---------------------------------------------------------------------------
sub load_config {
    my ($path) = @_;
    open(my $fh, '<', $path) or die "$PROG: cannot open config '$path': $!\n";
    my $section = '';
    while (my $line = <$fh>) {
        chomp $line;
        next if $line =~ /^\s*[#;]/ or $line =~ /^\s*$/;
        if ($line =~ /^\s*\[(\w+)\]\s*$/) {
            $section = $1;
            next;
        }
        if ($line =~ /^\s*([\w_]+)\s*=\s*(.*?)\s*$/) {
            my ($key, $val) = ($1, $2);
            $val =~ s/#.*$//;
            $val =~ s/\s+$//;
            $CONFIG{$key} = $val if exists $CONFIG{$key};
        }
    }
    close($fh);
}

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------
sub validate_log_dir {
    my ($dir) = @_;
    die "$PROG: log_dir '$dir' does not exist\n"     unless -e $dir;
    die "$PROG: log_dir '$dir' is not a directory\n" unless -d $dir;
    die "$PROG: log_dir '$dir' is not readable\n"    unless -r $dir;
    audit('INFO', "log_dir validated: $dir");
    return 1;
}

sub validate_line_length {
    my ($line) = @_;
    return length($line) <= $CONFIG{max_line_length};
}

sub validate_timestamp_field {
    my ($ts_str) = @_;
    return 0 unless defined $ts_str;
    return $ts_str =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
}

sub validate_pid_field {
    my ($pid) = @_;
    return 0 unless defined $pid;
    return $pid =~ /$CONFIG{pid_pattern}/;
}

sub validate_hostname_field {
    my ($host) = @_;
    return 0 unless defined $host;
    return $host =~ /$CONFIG{hostname_pattern}/;
}

# ---------------------------------------------------------------------------
# File collection — filter by age, size, name pattern
# ---------------------------------------------------------------------------
sub collect_log_files {
    my ($dir, $max_sz, $ret_days) = @_;
    my @files;
    my $cutoff = time() - ($ret_days * 86400);

    opendir(my $dh, $dir) or die "$PROG: cannot opendir '$dir': $!\n";
    for my $entry (sort readdir $dh) {
        next if $entry =~ /^\./;
        my $path = "$dir/$entry";
        next unless -f $path;
        my @st = stat($path);
        next unless @st;
        my ($size, $mtime) = ($st[7], $st[9]);
        next if $size < $CONFIG{min_size};
        if ($size > $max_sz) {
            audit('WARN', "skipping oversized file $entry ($size B)");
            $stats{skipped}++;
            next;
        }
        if ($mtime < $cutoff) {
            audit('INFO', "skipping aged-out file $entry");
            $stats{skipped}++;
            next;
        }
        push @files, { path => $path, size => $size, mtime => $mtime };
    }
    closedir($dh);
    return @files;
}

# ---------------------------------------------------------------------------
# Archival — gzip-compress files older than archive_days
# ---------------------------------------------------------------------------
sub maybe_archive {
    my ($file_info) = @_;
    return unless $CONFIG{enable_archive};
    return if $CONFIG{dry_run};

    my $cutoff = time() - ($CONFIG{archive_days} * 86400);
    return unless $file_info->{mtime} < $cutoff;

    my $dst_dir = $CONFIG{archive_dir};
    make_path($dst_dir) unless -d $dst_dir;

    my $src  = $file_info->{path};
    my $base = basename($src);
    my $dst  = "$dst_dir/$base";

    if ($CONFIG{compress_archive}) {
        my $rc = system('/bin/gzip', '-c', $src);
        if ($rc == 0) {
            rename($src, "$dst.gz");
            $stats{compressed}++;
        }
    } else {
        rename($src, $dst);
    }
    $stats{archived}++;
    audit('INFO', "archived $base");
}

# ---------------------------------------------------------------------------
# Alerting — buffer errors, flush when threshold reached
# ---------------------------------------------------------------------------
sub maybe_alert {
    my ($msg) = @_;
    return unless $CONFIG{enable_alerts};
    push @alert_buffer, $msg;
    if (scalar(@alert_buffer) >= $CONFIG{alert_threshold}) {
        flush_alerts();
    }
}

sub flush_alerts {
    return unless @alert_buffer;
    my $count = scalar @alert_buffer;
    audit('WARN', "flushing $count buffered alerts");
    @alert_buffer = ();
}

# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------
sub write_report {
    return unless $CONFIG{enable_report};
    return if $CONFIG{dry_run};

    my $ts   = strftime('%Y%m%d_%H%M%S', localtime);
    my $path = "$CONFIG{report_dir}/report_$ts.txt";

    open(my $fh, '>', $path) or do {
        audit('ERROR', "cannot write report to $path: $!");
        return;
    };

    printf $fh "Raven compliance report — %s\n", strftime('%F %T', localtime);
    printf $fh "%-20s %d\n", 'Total lines:',    $stats{total};
    printf $fh "%-20s %d\n", 'Matched:',        $stats{matched};
    printf $fh "%-20s %d\n", 'Skipped files:',  $stats{skipped};
    printf $fh "%-20s %d\n", 'Errors:',         $stats{errors};
    printf $fh "%-20s %d\n", 'Archived:',       $stats{archived};
    printf $fh "%-20s %d\n", 'Compressed:',     $stats{compressed};
    close($fh);
    audit('INFO', "report written to $path");
}

# ---------------------------------------------------------------------------
# Core — process a single log file line by line
# ---------------------------------------------------------------------------
sub process_log_file {
    my ($file_info, $pattern) = @_;

    my $path = $file_info->{path};
    open(my $fh, '<', $path) or do {
        audit('ERROR', "cannot open '$path': $!");
        $stats{errors}++;
        return;
    };

    my ($file_matched, $file_total, $file_errors) = (0, 0, 0);


    while (my $line = <$fh>) {
        chomp $line;

        unless (validate_line_length($line)) {
            $file_errors++;
            $stats{errors}++;
            maybe_alert("oversized line in " . basename($path));
            next;
        }

        $file_total++;
        $stats{total}++;

        if ($line =~ /$pattern/) {
            $file_matched++;
            $stats{matched}++;
        }
    }

    close($fh);

    audit('INFO', sprintf('%s: %d/%d matched, %d errors',
        basename($path), $file_matched, $file_total, $file_errors));

    maybe_archive($file_info);
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
sub print_summary {
    printf "Raven log analyser v%s\n", $VERSION;
    printf "  Total lines   : %d\n", $stats{total};
    printf "  Matched       : %d\n", $stats{matched};
    printf "  Skipped files : %d\n", $stats{skipped};
    printf "  Errors        : %d\n", $stats{errors};
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
sub main {
    open_audit_log();
    audit('INFO', "starting raven v$VERSION pid=$$ euid=$>");

    load_config($CONFIG_FILE) if -f $CONFIG_FILE;

    validate_log_dir($CONFIG{log_dir});

    my @files = collect_log_files(
        $CONFIG{log_dir},
        int($CONFIG{max_size}),
        int($CONFIG{retention_days}),
    );

    if (!@files) {
        audit('INFO', 'no eligible log files found');
        print_summary();
        close_audit_log();
        return 0;
    }

    for my $f (@files) {
        process_log_file($f, $CONFIG{loglevel_pattern});
    }

    flush_alerts();
    write_report();
    print_summary();
    close_audit_log();
    return 0;
}

exit main();