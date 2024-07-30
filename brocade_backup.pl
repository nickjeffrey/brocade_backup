#!/usr/bin/perl -w


# OUTSTANDING TASKS
# -----------------
#   1) Change use of nslookup to host so this script will work if DNS does not exist at the site
#   2) this script does not confirm that the supportSave files are created successfully
#   3) Add a subroutine to ping the NTP servers 
#   4) The brocade_backup.cfg must exist in the home directory, which must also be the current directory.  See if you can make this a bit more robust.
#   5) Add functionality to brocade_backup.cfg config file to hold site-specific data (target SCP server, passwords, etc)
#   6) Ping the active NTP server (unless it is LOCL)

# CHANGE LOG
# ---------- 
#  2008/10/06	njeffrey	Script created
#  2009/07/20	njeffrey	Add userConfig command
#  2011/04/29	njeffrey	Assorted documentation updates and bug fixes
#  2011/11/22	njeffrey	Change IP addresses for switches moved to new DR site
#  2011/11/28	njeffrey	Break script up into subroutines
#  2011/11/28	njeffrey	Add $verbose flag for debugging
#  2011/11/28	njeffrey	Add more error checking
#  2011/12/07	njeffrey	Add SupportSave command
#  2011/12/07	njeffrey	Add email alert if configupload.$host file is more than 2 days old
#  2012/05/24	njeffrey	Break the name resolution check out into its own subroutine
#  2012/05/24	njeffrey	Check error log for zoning errors, failed logins, etcl
#  2012/05/25	njeffrey	Update error log checks to only send a single warning for multiple errors of the same type
#  2012/05/25	njeffrey	Add warning for high temperature alerts in error log
#  2015/08/12   njeffrey    	Remove dependency on Net::Telnet perl module - just use /usr/bin/ssh instead
#  2015/08/12	njeffrey 	Switch from telnet to ssh, as Brocade switches in Pureflex chassis do not allow telnet
#  2015/08/12	njeffrey	Switch the configUpload and supportSave commands from FTP to SCP - Brocade switches in PureFlex chassis do not allow FTP 
#  2015/08/14	njeffrey	Bug fix - typo in check for configupload.$host file
#  2015/08/14	njeffrey	Add get_switch_ip_info subroutine
#  2021/03/26	njeffrey	Commented out these commands that do not exist in FabOS 8.x  agtcfgShow chassisconfig httpcfgshow syslogdIpShow 
#  2021/03/26	njeffrey	Commented out these commands that do not exist in FabOS 8.x  snmpMibCapShow switchStatusShow syslogdipshow
#  2022/01/06	njeffrey	Add "-r admin -c admin -l 1-128" parameters to the Brocade userConfig command (required by newer versions of FabOS)
#  2022/01/06	njeffrey	Add --verbose --report --host  parametess
#  2022/01/07	njeffrey	Add "-o PubkeyAuthentication=yes -o PasswordAuthentication=no" parameters to SSH command to avoid interactive password prompts
#  2022/03/02	njeffrey	Add command: snmpconfig --show accessControl
#  2022/05/16	njeffrey	Add ping_dns_servers subroutine
#  2022/05/16	njeffrey	Send email report in HTML format so we can use green=good red=bad colors
#  2022/05/24	njeffrey	Add set_time subroutine for environments that do not have NTP servers defined
#  2022/05/30	njeffrey	Add get_fabos_version subroutine 
#  2022/05/30	njeffrey	FabOS 8.2.2 requires -P 22 parameter to specify the TCP port on the configUpload command
#  2023/01/03	njeffrey	Add read_config_file subroutine
#  2024/07/29   njeffrey        Remove -p MySecretPassword parameter from supportSave command, because we have switched from FTP to SCP, so we can use SSH key pair auth instead of hardcoded password




# NOTES
# -----
#
# This script will pull the configuration information from a Brocade fibre switch
# and dump them into a directory where they will get backed up to tape during the regular filesystem backups.
#
# You will need an identical userid/password on all the Brocade fibre switches.  The following example shows how
# to create a userid called "backup" with a role of "admin" and a descriptive message.  It would be nice if we
# could just create a user with the "operator" role, but we need the "admin" role to run the configUpload command.
#    ssh <switchname>
#    userid: admin
#    password: ******
#    userConfig --add backup -d "used by automated scripts" -r admin -c admin -l 1-128
#    sshutil allowuser backup
#    sshutil importpubkey
#       Enter user name for whom key is imported:backup
#       Enter IP address:165.89.12.156  # remote host ip
#       Enter remote directory:/home/brocade/.ssh
#       Enter public key name(must have .pub suffix):id_rsa.pub
#       Enter login name:brocade
#       Password: brocade_user_password_on_unix_box
#       public key is imported successfully.
#    exit
#
# We also want the Brocade switch to ssh into a remote UNIX host without a password
# so we can run the configUpload and supportSave commands without entering a password.
# This means we will want to generate public/private keys on the Brocade switch
# and put the public key on the remote UNIX box.
#    ssh <switchname>
#    userid: backup
#    password: *****
#    sshutil genkey -rsa
#    sshutil exportpubkey
#       Enter IP address: 192.168.38.244 #remote host IP
#       Enter remote directory:/home/brocade/.ssh
#       Enter login name:brocade
#       Password:SomeSuperSecretPassword
#       public key out_going.pub is exported successfully
#    exit
# Now the public key has been saved as unixbox:/home/brocade/.ssh/out_going.pub
# You will need to append this public key to the authorized_keys file on the UNIX box.
#     $ hostname
#       unixbox
#     $ whoami
#       brocade
#     $ cat /home/brocade/.ssh/out_going.pub >> /home/brocade/.ssh/authorized_keys
#     $ chmod 600 /home/brocade/.ssh/authorized_keys
#
#
# It is assumed that this script is being run on a UNIX-like server with a running SSH/SCP daemon.  
# When running the "configUpload" command on each Brocade switch, a copy of the switch config will be sent via SCP
#
# It is assumed that a user account on the SCP server exists (because this script chown's to that user)
# Example userid creation for AIX:
#     mkuser -a id=30007 maxage=0 home=/home/brocade brocade
#     passwd brocade
#     pwdadm -c brocade
#     echo Creating SSH key pair for brocade user
#     su - brocade
#     ssh-keygen 
#
# Example userid creation for Linux:
#     useradd --uid=30007 --home-dir=/home/brocade brocade
#     passwd brocade
#     echo Creating SSH key pair for brocade user
#     su - brocade
#     ssh-keygen 
#
# This script is configured to run from a cron job on a UNIX box (often a NIM server)
# This script is run from the crontab of the brocade userid
# If you have multiple backup servers, just stagger the backups by an hour so we have backups at multiple sites
#   45 4 * * 1 /home/brocade/brocade_backup.pl >/dev/null 2>&1    #backup Brocade configs Mondays at 04:45



# TROUBLESHOOTING
# ---------------
#  1) Confirm you can ssh into the switch with the $ssh_userid and $password in this script
#  2) Confirm you can SCP into $scpserver with $scpuser / $scppass 
#  3) Confirm the directory on the SCP server that the files are sent to is owned by $scpuser
#  4) Confirm there are no firewalls preventing the SSH traffic used by this script
#  5) Confirm that ssh has not been disabled on any of the Brocade switches
#  6) Confirm the $userid on the Brocade switch has the "admin" role, which is required to run configupload
#  7) Confirm each brocade switch can perform name resolution to get the IP of the SCP server with the dnsconfig command
#  8) Confirm that all brocade switches in your environment are listed in the @hostname array 
#  9) Confirm this script is running from the SCP server, because we check the local filesystem for the configupload file
# 10) Confirm that $scpuser exists in /etc/passwd on the system this script runs from 
# 11) Confirm that $scpuser does not have an expired password (try to SCP or SSH in manually to confirm) 
# 12) Confirm the host you are running this script from can query a DNS server for name resolution (check /etc/resolv.conf)
# 13) Confirm SSH works in *both* directions.  There might be firewalls that only allow SSH in one direction.




# DISASTER RECOVERY PROCEDURE
# ---------------------------
#  In the event that a Brocade switch is lost/destroyed/corrupted, and you want to restore the
#  backed up version of the config, you can use this procedure:
#    1) Get the switch on the network 
#    2) Login to the switch via the local serial console port, or SSH in over the network
#    3) Use the "ConfigDownload" command to download the switchname.config.txt file that was backed up
#    4) Confirm IP address, subnet mask, default gateway is correct with: ipAddrShow
#    5) Confirm DNS config information is correct with: dnsConfig --show
#    6) Confirm SNMP configuration is correct with: snmpConfig --show snmpv1
#    7) Confirm "backup" userid exists with: userConfig --show backup
#    8) The SSH host key may have changed if there was a hardware replacement, confirm this backup script can automatically login to the new switch.
#    9) If required, re-run the SSH key setup process described in this script for setting up a new switch




use strict;							#enforce good coding practices
use Getopt::Long;                                       	#allow --long-switches to be used as parameters



my ($date,$brocade_userid,$verbose,$report,$configupload,$supportsave,$localhost,$now,$opt_h,$opt_v,$opt_H,$opt_r,$opt_c,$opt_s,$opt_d);
my ($outputdir,$scpserver,$scpuser,$scppass,@cmds,@files,$file,$config_file);
my ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks);	#file stat fields
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst);					#time fields
my ($nslookup,$ssh,$ping,$ping_status,$host,@hostname,$cmd,$key,%switch_details);
my ($from,$to,$subject,$sendmail,$readme,$output_file,$bgcolor);				#for sending email report
my ($errlog_failedlogin,$errlog_zoneconflict,$errlog_domainid,$errlog_hitemp);			#messages in error report
my ($dnscheck);




#declare variables
$date                = `date`; chomp $date;
$brocade_userid      = "backup";  				#username to login to brocade switches
$brocade_userid      = "admin";  				#username to login to brocade switches
$host                = "";					#initialize variable
$ssh                 = "/usr/bin/ssh";				#location of binary
$ping_status         = "";					#flag for checking to see if ping     test succeeds
$verbose             = "no";					#yes/no flag to increase verbosity of output to aid debugging
$report              = "";					#yes/no flag to send an email report when the backup comples
$configupload        = "";					#yes/no flag to run configupload command to save Brocade configs to SCP server
$supportsave         = "";					#yes/no flag to save diagnostic info (takes ~10-15 minuts per device)
$outputdir           = "/home/brocade";				#output directory used for text dumps of command output
$localhost           = `hostname -s`; chomp $localhost;		#hostname of local machine
$sendmail            = "/usr/lib/sendmail";			#location of sendmail binary used for emailing report
$readme              = "$outputdir/readme.txt";			#create a readme file explaining how to restore configs
$output_file         = "$outputdir/brocade_backup.html"; 	#location of file containing the HTML report sent via email to the sysadmin
$config_file         = "$outputdir/brocade_backup.cfg"; 	#location of file containing site-specific details $to $from $subject $host
$errlog_failedlogin  = 0;					#initialize counter
$errlog_zoneconflict = 0;					#initialize counter
$errlog_domainid     = 0;					#initialize counter
$errlog_hitemp       = 0;					#initialize counter
@cmds            = ( 
                     #"agtcfgShow",				#does not exist in FabOS 8.x
                     "cfgShow",
                     "configShow", 				# causes timeout on firmware 5.3.x
                     #"chassisconfig",				#does not exist in FabOS 8.x
                     "chassisShow",
                     "dnsConfig --show",
                     "fabricShow",
                     "fanShow",
                     "firmwareshow",
                     "fspfshow",
                     "haShow",
                     #"httpcfgshow",				#does not exist in FabOS 8.x
                     "ipAddrShow",
                     "licenseShow",
                     #"syslogdIpShow",				#does not exist in FabOS 8.x
                     "memShow",
                     "nsAliasShow",
                     "nsAllShow",
                     "nsShow",
                     "pkishow",
                     "portBufferShow",
                     "portCfgShow",
                     "portErrShow",
                     "portTestShow",
                     "psShow",
                     "secglobalshow",
                     "secstatsshow",
                     "sfpshow",
                     "snmpConfig --show snmpv1",
                     "snmpConfig --show accessControl",
                     #"snmpMibCapShow",				#does not exist in FabOS 8.x
                     "switchShow",
                     #"switchStatusShow",			#does not exist in FabOS 8.x
                     "switchuptime",
                     #"supportShow",  				# causes timeouts on firmware 5.3.x
                     #"syslogdipshow",				#does not exist in FabOS 8.x
                     "tempshow",
                     #"topologyShow",				# causes timeout issues on brocade firmware 7.4.2, expecting extra carriage return after command
                     "trunkShow",
                     "tsClockServer",
                     "tsTimeZone",
                     "uptime",
                     #"uRouteShow",  				# causes timeout issues on brocade firmware 5.3.x and 7.4.2
                     #"userConfig --show -a",			# causes timeout issues on brocade firmware 6.0.x
                     "version",
                     "zoneShow",
                     "wwn",
                   );




sub get_options {
   #
   # this gets the command line parameters provided by the users
   #
   print "Running get_options subroutine \n" if ($verbose eq "yes");
   Getopt::Long::Configure('bundling');
   GetOptions(
      "h"   => \$opt_h, "help"           => \$opt_h,
      "v"   => \$opt_v, "verbose"        => \$opt_v,
      "H=s" => \$opt_H, "host=s"         => \$opt_H,
      "r=s" => \$opt_r, "report=s"       => \$opt_r,
      "c=s" => \$opt_c, "configupload=s" => \$opt_c,
      "s=s" => \$opt_s, "supportsave=s"  => \$opt_s,
      "d=s" => \$opt_d, "dnscheck=s"     => \$opt_d,
   );
   #
   # If the user supplied the -h or --help switch, give them some help.
   #
   if( defined( $opt_h ) ) {
      print "Use this syntax: \n";
      print "   $0 --help        \n";
      print "   $0 --verbose               (increase output for debugging \n";
      print "   $0 --dnscheck=yes|no       (check to see if hostnames are in DNS, defaults to yes)\n";
      print "   $0 --report=yes|no         (send an email report to sysadmin, defaults to yes)\n";
      print "   $0 --configupload=yes|no   (save config backup, defaults to yes) \n";
      print "   $0 --supportsave=yes|no    (save diagnostic info, defaults to yes) \n";
      print "   $0 --host=sw1,sw2,sw3,sw4  (optional list of switches to backup) \n";
      print "                              (if --host=xxx not provided, read from brocade_backup.cfg config file) \n";
      exit;
   }
   #
   # If the user supplied the --verbose switch, increase output verbosity
   #
   if( defined( $opt_v ) ) {
      $verbose = "yes";
   } else {
      $verbose = "no";
   }
   #
   # If the user supplied the --report=yes|no parameter, decide if report needs to be sent.
   #
   if( defined( $opt_r ) ) {
      $report = "yes";		#default to yes
      if ( $opt_r eq "yes" ) {
         $report = "yes";
         print "   --report=yes parameter was specified, will send email report to sysadmin \n" if ($verbose eq "yes");
      }
      if ( $opt_r eq "no" ) {
         $report = "no";
         print "   --report=no parameter was specified, skipping email report to sysadmin \n" if ($verbose eq "yes");
      }
   } else {
      $report = "yes";
      print "   --report=yes|no parameter not specified, defaulting to yes \n" if ($verbose eq "yes");
   }
   #
   # If the user supplied the --configupload=yes|no parameter, decide if diagnostic info needs to be saved
   #
   if( defined( $opt_c ) ) {
      $configupload = "yes";		#default to yes
      if ( $opt_c eq "yes" ) {
         $configupload = "yes";
         print "   --configupload=yes parameter was specified, will save configuration backup \n" if ($verbose eq "yes");
      }
      if ( $opt_c eq "no" ) {
         $configupload = "no";
         print "   --configupload=no parameter was specified, skipping configuration backup \n" if ($verbose eq "yes");
      }
   } else {
      $configupload = "yes";
      print "   --configupload=yes|no parameter not specified, defaulting to yes \n" if ($verbose eq "yes");
   }
   #
   # If the user supplied the --dnscheck=yes|no parameter, decide if name resolution needs to be checked
   #
   if( defined( $opt_d ) ) {
      $dnscheck = "yes";		#default to yes
      if ( $opt_d eq "yes" ) {
         $dnscheck = "yes";
         print "   --dnscheck=yes parameter was specified, will validate name resolution \n" if ($verbose eq "yes");
      }
      if ( $opt_d eq "no" ) {
         $dnscheck = "no";
         print "   --dnscheck=no parameter was specified, skipping name resolution check \n" if ($verbose eq "yes");
      }
   } else {
      $dnscheck = "yes";
      print "   --dnscheck=yes|no parameter not specified, defaulting to yes \n" if ($verbose eq "yes");
   }
   #
   # If the user supplied the --supportsave=yes|no parameter, decide if diagnostic info needs to be saved
   #
   if( defined( $opt_s ) ) {
      $supportsave = "yes";		#default to yes
      if ( $opt_s eq "yes" ) {
         $supportsave = "yes";
         print "   --supporsave=yes parameter was specified, will save diagnostic info \n" if ($verbose eq "yes");
      }
      if ( $opt_s eq "no" ) {
         $supportsave = "no";
         print "   --supportsave=no parameter was specified, skipping collection of diagnostic info \n" if ($verbose eq "yes");
      }
   } else {
      $supportsave = "yes";
      print "   --supportsave=yes|no parameter not specified, defaulting to yes \n" if ($verbose eq "yes");
   }
   #
   # If the user supplied the --host=xxx,yyy,zzz parameter, figure out which switches to backup
   # Alternatively, if the --host=xxx,yyy,zzz parameter was not provided, look for the brocade_backup.cfg config file to get the device names from
   #
   if(defined($opt_H)) {
      @hostname = split(',', $opt_H);
      print "   These devices will be backed up: @hostname \n" if ($verbose eq "yes");
   } elsif ( -f "brocade_backup.cfg" ) {
      open (IN,"brocade_backup.cfg") or die "Cannot open brocade_backup.cfg for reading $1 \n";
      while (<IN>) {								#read a line from the filehande
         if ( /^host=(.*)/ ) {							#find the line that looks like host=xxx,yyy,zzz
            @hostname = split(',', $1);
         }									#end of if block
      } 									#end of while loop
      close IN;									#close filehandle
   } else  {
      print "Could not determine remote devices to backup.  Please check script syntax with:   $0 --help \n";
      exit;
   }
}                       #end of subroutine




sub sanity_checks {
   #
   # confirm the nslookup binary exists and is executable
   #
   print "running sanity_checks subroutine \n" if ($verbose eq "yes");
   #
   $nslookup = "/usr/local/bin/nslookup" if ( -e "/usr/local/bin/nslookup" ); 		
   $nslookup = "/usr/sbin/nslookup"      if ( -e "/usr/sbin/nslookup" );		
   $nslookup = "/usr/bin/nslookup"       if ( -e "/usr/bin/nslookup" );		
   if ( ! -e "$nslookup" ) {									#confirm nslookup binary could be found
      print "ERROR: Could not find nslookup binary \n";						#display error message for user
      exit;											#exit script
   }												#end of if block
   if ( ! -x "$nslookup" ) {									#confirm nslookup binary is executable
      print "ERROR: nslookup binary is not executable by the current user\n";			#display error message for user
      exit;											#exit script
   }												#end of if block
   #
   #
   # confirm the sendmail binary exists and is executable
   #
   $sendmail = "/usr/lib/sendmail"        if ( -e "/usr/lib/sendmail" ); 			#sendmail location on AIX
   $sendmail = "/usr/sbin/sendmail"       if ( -e "/usr/sbin/sendmail" ); 			#sendmail location on FreeBSD/RHEL
   if ( ! -e "$sendmail" ) {									#confirm sendmail binary could be found
      print "ERROR: Could not find sendmail binary \n";						#display error message for user
      exit;											#exit script
   }												#end of if block
   if ( ! -x "$sendmail" ) {									#confirm sendmail binary is executable
      print "ERROR: sendmail binary is not executable by the current user\n";			#display error message for user
      exit;											#exit script
   }												#end of if block
   #
   #
   # confirm the ping binary exists and is executable
   #
   $ping     = "/sbin/ping"                 if ( -e "/sbin/ping" );				#ping location on FreeBSD
   $ping     = "/usr/sbin/ping"             if ( -e "/usr/sbin/ping" );				#ping location on AIX
   $ping     = "/bin/ping"                  if ( -e "/bin/ping" );				#ping location on Linux
   if ( ! -e "$ping" ) {									#confirm ping binary could be found
      print "ERROR: Could not find ping binary \n";						#display error message for user
      exit;											#exit script
   }												#end of if block
   if ( ! -x "$ping" ) {									#confirm ping binary is executable
      print "ERROR: ping binary is not executable by the current user\n";			#display error message for user
      exit;											#exit script
   }												#end of if block
   #
   #
   # confirm the ssh binary exists and is executable
   #
   if ( ! -e "$ssh" ) {										#confirm ssh binary could be found
      print "ERROR: Could not find ssh binary \n";						#display error message for user
      exit;											#exit script
   }												#end of if block
   if ( ! -x "$ssh" ) {										#confirm ping binary is executable
      print "ERROR: ssh binary is not executable by the current user\n";			#display error message for user
      exit;											#exit script
   }												#end of if block
   # Add switches to ssh binary to ensure we do not an interactive password prompt
   $ssh = "$ssh -o PubkeyAuthentication=yes -o PasswordAuthentication=no";
}												#end of subroutine




sub read_config_file {
   #
   print "running read_config_file subroutine \n" if ($verbose eq "yes");
   #
   if ( ! -f "$config_file" ) {									#confirm the config file exists
      print "ERROR: cannot find config file $config_file - exiting script \n";
      exit;
   } 												#end of if block
   if ( -z "$config_file" ) {									#confirm the config file is larger than zero bytes
      print "ERROR: config file $config_file is zero size - exiting script \n";
      exit;
   } 												#end of if block
   print "   opening config file $config_file for reading \n" if ($verbose eq "yes");
   open(IN,"$config_file") or die "Cannot read config file $config_file $! \n"; 		#open file for reading
   while (<IN>) {                                                                            	#read a line from the command output
      #
      # email address details 
      #
      $to                    = $1              if (/^to=([a-zA-Z0-9,_\-\@\.]+)/);		#find line in config file
      $from                  = $1              if (/^from=([a-zA-Z0-9_\-\@\.]+)/);		#find line in config file
      $subject               = $1              if (/^subject=([a-zA-Z0-9 _\-\@]+)/);		#find line in config file
      #
      # SCP backup server details 
      #
      $scpserver             = $1              if (/^scpserver=([a-zA-Z0-9_\-\@\.]+)/);		#find line in config file
      $scpuser               = $1              if (/^scpuser=([a-zA-Z0-9_\-\.]+)/);		#find line in config file
      $scppass               = $1              if (/^scppass=([a-zA-Z0-9_\-\@]+)/);		#find line in config file
   }                                                                                         	#end of while loop
   close IN;                                                                                 	#close filehandle
   #
   # check to see if to/from/subject are populated
   #
   unless(defined($to)) {
      print "ERROR: Could not find line similar to to=helpdesk\@example.com in config file $config_file \n";
      exit;
   }												#end of unless block
   unless(defined($from)) {
      print "ERROR: Could not find line similar to from=alerts\@example.com in config file $config_file \n";
      exit;
   }												#end of unless block
   unless(defined($subject)) {
      print "ERROR: Could not find line similar to subject=BigCorp daily status check in config file $config_file \n";
      exit;
   }												#end of unless block
   unless(defined($scpserver)) {
      print "ERROR: Could not find line similar to scpserver=server01.example.com in config file $config_file \n";
      exit;
   }												#end of unless block
   unless(defined($scpuser)) {
      print "ERROR: Could not find line similar to scpuser=brocade in config file $config_file \n";
      exit;
   }												#end of unless block
   unless(defined($scppass)) {
      print "ERROR: Could not find line similar to scppass=MySecretPassword in config file $config_file \n";
      exit;
   }												#end of unless block
   print "   to:$to  from:$from  subject:$subject scpserver=$scpserver scpuser=$scpuser scppass=$scppass \n" if ($verbose eq "yes");
}												#end of subroutine




sub build_hash {
   #
   print "running build_hash subroutine \n" if ($verbose eq "yes");
   #
   # Figure out the hostname of each device, and build a perl hash (aka associative array) to hold details about each device
   #
   foreach $host ( @hostname ) {
      $switch_details{$host}{hostname}=$host;							#assign hash key for each hostname
      $switch_details{$host}{nslookup_status}="unknown";					#initialize hash element to avoid undef errors
   }												#end of foreach loop
}												#end of subroutine




sub check_name_resolution {
   #
   print "running check_name_resolution subroutine \n" if ($verbose eq "yes");
   return unless ($dnscheck eq "yes");								#break out of subroutine
   #
   # Connect to each device to get the configuration details
   #
   foreach $key (sort keys %switch_details) {                 					#loop through for each remote device
      #
      # confirm valid name resolution exists for each device
      print "   Attempting to validate name resolution for host: $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
      #
      next unless ( -e "/etc/resolv.conf" );							#skip hosts without a resolv.conf file
      #
      $switch_details{$key}{nslookup_status} = "unknown";					#initialize hash element
      if( ! open( NSLOOKUP, "$nslookup $switch_details{$key}{hostname} 2>&1|" ) ) {
         print STDERR "error - cannot perform name resolution for host $switch_details{$key}{hostname}.  Please add to DNS.\n\n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $localhost:$0 error - cannot resolve host $switch_details{$key}{hostname}\n\n";
         print MAIL "Cannot perform name resolution for Brocade fibre channel switch $switch_details{$key}{hostname}.   Working name resolution is required for the Brocade switches to perform regular config backups. Please add $switch_details{$key}{hostname} to DNS.\n\n";
         next;											#skip to next host in foreach loop
      }												#end of if block
      while (<NSLOOKUP>) {                        						#read a line from STDIN
         if (/Address:/) {									#look for error message from nslookup
            $switch_details{$key}{nslookup_status} = "ok";					#set flag value for hash element
         }											#end of if block
         if (/failed/) {									#look for error message from nslookup
            $switch_details{$key}{nslookup_status} = "failed";					#set flag value for hash element
         }											#end of if block
         if (/NXDOMAIN/) {									#look for error message from nslookup
            $switch_details{$key}{nslookup_status} = "failed";					#set flag value for hash element
         }											#end of if block
         if (/SERVFAIL/) {									#look for error message from nslookup
            $switch_details{$key}{nslookup_status} = "failed";					#set flag value for hash element
         }											#end of if block
      }												#end of while loop
      close NSLOOKUP;										#close filehandle
      if ( $switch_details{$key}{nslookup_status} eq "failed" ) {				#check for flag value
         print STDERR "error - cannot perform name resolution for host $switch_details{$key}{hostname}.  Please add to DNS.\n\n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $localhost:$0 error - cannot resolve host $switch_details{$key}{hostname} \n\n";
         print MAIL "Cannot perform name resolution for Brocade fibre channel switch $switch_details{$key}{hostname}.   Working name resolution is required for the Brocade switches to perform regular config backups.  Please add $switch_details{$key}{hostname} to DNS.\n\n";
         next;											#skip to next host in foreach loop
      }												#end of if block
   }												#end of foreach block
}												#end of subroutine




sub ping_brocade_switch {
   #
   print "running ping_brocade_switch subroutine \n" if ($verbose eq "yes");
   #
   # Confirm each Brocade switch responds to ping
   #
   foreach $key (sort keys %switch_details) {                 						#loop through for each remote device
      #
      # ping remote hostname 
      #
      $switch_details{$key}{ping_status} = "unknown";							#initialize hash element
      print "   attempting to ping host: $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
      if( ! open( PING, "$ping -c 4 $switch_details{$key}{hostname} |" ) ) {
         print STDERR "error - cannot ping host $switch_details{$key}{hostname}.  $! \n\n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $localhost:$0 error - cannot ping host $host\n\n";
         print MAIL "Cannot ping host $switch_details{$key}{hostname}.  Please investigate. \n\n";
         next;
      }
      while (<PING>) {											#read a line from STDIN
         $switch_details{$key}{ping_status} = "failed" if ( /100% packet loss/ ); 			#using ping-c 2, so options are 100% 50% 0% packet loss
         $switch_details{$key}{ping_status} = "ok"     if (  /50% packet loss/ ); 			#using ping-c 2, so options are 100% 50% 0% packet loss
         $switch_details{$key}{ping_status} = "ok"     if (  / 0% packet loss/ ); 			#using ping-c 2, so options are 100% 50% 0% packet loss
      }													#end of while loop
      close PING;											#close filehandle
      if ( $switch_details{$key}{ping_status} eq "ok" ) {						#check for flag value
         print "   ping success to $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
      }													#end of if block
      if ( $switch_details{$key}{ping_status} eq "failed" ) {						#check for flag value
         print STDERR "error - cannot ping host $switch_details{$key}{hostname}.  $! \n\n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $localhost:$0 error - cannot ping host $switch_details{$key}{hostname} \n\n";
         print MAIL "Cannot ping host $switch_details{$key}{hostname}.  Please investigate. \n\n";
      }													#end of if block
      close MAIL;											#close filehandle
   }													#end of foreach loop
}													#end of subroutine
      



sub get_fabos_version {
   #
   print "running get_fabos_version subroutine \n" if ($verbose eq "yes");
   #
   # Sample output:
   # SANSW1:admin> firmwareshow
   # Appl     Primary/Secondary Versions
   # ------------------------------------------
   # FOS      v8.2.2b
   #          v8.2.2b
   #
   foreach $key (sort keys %switch_details) {                 						#loop through for each remote device
      $switch_details{$key}{fabos_version} = "unknown";							#initialize hash element to avoid undef errors
      $cmd = "firmwareshow"; 
      print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
      open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or die "$!\n";
      while (<SSH>) {
         if ( /FOS +([a-z0-9\.]+)/) {
            $switch_details{$key}{fabos_version} = $1;							#assign to hash element
            print "   found FabOS version $switch_details{$key}{fabos_version} on $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
         }  												#end of if block
      } 												#end of while loop
      close SSH; 											#close filehandle
   } 									 				#end of foreach loop
}													#end of subroutine




sub get_dns_servers {
   #
   print "running get_dns_servers subroutine \n" if ($verbose eq "yes");
   #
   # Connect to each device to look at IP address, DNS settings, NTP settings, etc
   #
   # You should see command output similar to:
   #      Domain Name Server Configuration Information
   #      ____________________________________________
   #
   #      Domain Name            = example.com
   #      Name Server IP Address = 10.10.32.161
   #      Name Server IP Address = 10.10.32.162
   #
   #
   foreach $key (sort keys %switch_details) {                 			#loop through for each remote device
      #
      $cmd = "dnsconfig --show"; 
      print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
      open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or die "$!\n";
      while (<SSH>) {
         if ( / Name Server IP Address = ([0-9\.]+)/) {
            if ( ( defined( $switch_details{$key}{nameserver1})) && (!defined( $switch_details{$key}{nameserver2})) ) {	#neither nameserver1 or nameserver2 are defined, so this must be nameserver1
               $switch_details{$key}{nameserver2} = $1;				#assign to hash element
               print "   found nameserver2 $switch_details{$key}{nameserver2} from Brocade switch $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
            }  									#end of if block
            if ( (!defined( $switch_details{$key}{nameserver1})) && (!defined( $switch_details{$key}{nameserver2})) ) {	#neither nameserver1 or nameserver2 are defined, so this must be nameserver1
               $switch_details{$key}{nameserver1} = $1;				#assign to hash element
               print "   found nameserver1 $switch_details{$key}{nameserver1} from Brocade switch $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
            }  									#end of if block
         }  									#end of if block
      } 									#end of while loop
      close SSH; 								#close filehandle
      if ( (!defined($switch_details{$key}{nameserver1})) && (!defined($switch_details{$key}{nameserver2})) ) {
         print "ERROR: brocade switch $switch_details{$key}{hostname} does not have any DNS defined, so it cannot resolve the name of the backup server.  Please run dnsconfig on the brocade switch to setup the DNS servers \n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $localhost:$0 error - Brocade switch $switch_details{$key}{hostname} does not have defined DNS servers \n\n";
         print MAIL "Please define DNS servers on Brocade switch $switch_details{$key}{hostname} by running the dnsconfig command.  Working name resolution is required for the Brocade switches to perform regular config backups. \n\n";
         close MAIL;								#close filehandle
      } 									#end of if block
   }										#end of foreach loop
}										#end of subroutine




sub ping_dns_servers {
   #
   print "running ping_dns_servers subroutine \n" if ($verbose eq "yes");
   #
   foreach $key (sort keys %switch_details) {                 						#loop through for each remote device
      #
      # Try to ping the first DNS server
      #
      $switch_details{$key}{nameserver1_ping_status} = "unknown";					#initialize hash element
      if (defined($switch_details{$key}{nameserver1})) {						#skip if the Brocade switch does not have nameserver1 defined
         print "   attempting to ping nameserver1 $switch_details{$key}{nameserver1} from Brocade switch $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
         $cmd = "$ssh $brocade_userid\@$switch_details{$key}{hostname} ping -c 2 $switch_details{$key}{nameserver1}";
         print "   running command $cmd \n" if ($verbose eq "yes");
         open(PING,"$cmd  |") or die "$!\n";
         while (<PING>) {										#read a line from STDIN
            $switch_details{$key}{nameserver1_ping_status} = "failed" if ( /100% packet loss/ ); 	#using ping-c 2, so options are 100% 50% 0% packet loss
            $switch_details{$key}{nameserver1_ping_status} = "ok"     if (  /50% packet loss/ ); 	#using ping-c 2, so options are 100% 50% 0% packet loss
            $switch_details{$key}{nameserver1_ping_status} = "ok"     if (  / 0% packet loss/ ); 	#using ping-c 2, so options are 100% 50% 0% packet loss
         }												#end of while loop
         close PING;											#close filehandle
         #
         # send an alert if required
         #
         if ( $switch_details{$key}{nameserver1_ping_status} eq "ok" ){ 	
            print "   successful ping response from nameserver1 $switch_details{$key}{nameserver1} from Brocade switch $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
         } 												#end of if block
         if ( $switch_details{$key}{nameserver1_ping_status} eq "failed" ){ 	
            print "   no ping response from nameserver1 $switch_details{$key}{nameserver1} from Brocade switch $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
            open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
            print MAIL "From: $from\n";
            print MAIL "To: $to\n";
            print MAIL "Subject: $localhost:$0 error - Brocade switch $switch_details{$key}{hostname} ping failure to defined nameserver1  $switch_details{$key}{nameserver1} \n\n";
            print MAIL "Brocade switch $switch_details{$key}{hostname} is trying to use $switch_details{$key}{nameserver1} for name resolution, but $switch_details{$key}{nameserver1} is not responding to ping.  Working name resolution is required for the Brocade switches to perform regular config backups.  Please define working DNS servers on Brocade switch $switch_details{$key}{hostname} with the dnsconfig command.   \n\n";
            close MAIL;											#close filehandle
         } 												#end of if block
      }													#end of if block
      #
      # Try to ping the second DNS server
      #
      $switch_details{$key}{nameserver2_ping_status} = "unknown";					#initialize hash element
      if (defined($switch_details{$key}{nameserver2})) {						#skip if the Brocade switch does not have nameserver2 defined
         print "   attempting to ping nameserver2 $switch_details{$key}{nameserver2} from Brocade switch $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
         $cmd = "$ssh $brocade_userid\@$switch_details{$key}{hostname} ping -c 2 $switch_details{$key}{nameserver2}";
         print "   running command $cmd \n" if ($verbose eq "yes");
         open(PING,"$cmd  |") or die "$!\n";
         while (<PING>) {										#read a line from STDIN
            $switch_details{$key}{nameserver2_ping_status} = "failed" if ( /100% packet loss/ ); 	#using ping-c 2, so options are 100% 50% 0% packet loss
            $switch_details{$key}{nameserver2_ping_status} = "ok"     if (  /50% packet loss/ ); 	#using ping-c 2, so options are 100% 50% 0% packet loss
            $switch_details{$key}{nameserver2_ping_status} = "ok"     if (  / 0% packet loss/ ); 	#using ping-c 2, so options are 100% 50% 0% packet loss
         }												#end of while loop
         close PING;											#close filehandle
         #
         # send an alert if required
         #
         if ( $switch_details{$key}{nameserver2_ping_status} eq "ok" ){ 	
            print "   successful ping response from nameserver2 $switch_details{$key}{nameserver2} from Brocade switch $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
         } 												#end of if block
         if ( $switch_details{$key}{nameserver2_ping_status} eq "failed" ){ 	
            print "   no piong response from nameserver2 $switch_details{$key}{nameserver2} from Brocade switch $switch_details{$key}{hostname} \n" if ($verbose eq "yes");
            open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
            print MAIL "From: $from\n";
            print MAIL "To: $to\n";
            print MAIL "Subject: $localhost:$0 error - Brocade switch $switch_details{$key}{hostname} ping failure to defined nameserver2  $switch_details{$key}{nameserver2} \n\n";
            print MAIL "Brocade switch $switch_details{$key}{hostname} is trying to use $switch_details{$key}{nameserver2} for name resolution, but $switch_details{$key}{nameserver2} is not responding to ping.  Working name resolution is required for the Brocade switches to perform regular config backups.  Please define working DNS servers on Brocade switch $switch_details{$key}{hostname} with the dnsconfig command.   \n\n";
            close MAIL;											#close filehandle
         } 												#end of if block
      }													#end of if block
   }													#end of foreach loop
}													#end of subroutine




 
sub get_config_details {
   #
   print "running get_config_details subroutine \n" if ($verbose eq "yes");
   #
   # Connect to each device to get the configuration details
   #
   foreach $key (sort keys %switch_details) {                 						#loop through for each remote device
      #
      # Run an assortment of commands to show various config details about the switch.
      # The output will be stored in a variety of text files for easy reference.
      #
      next if ( $switch_details{$key}{ping_status} eq "failed" );					#skip any devices that did not respond to ping
      foreach $cmd ( @cmds ) {
         $file= $cmd;											#set output filename to same as command name
         $file =~ s/ /_/g;										#change spaces in output filename to underscores
         #
         # 
         # confirm the destination directory exists
         #
         mkdir ("$outputdir")                                             if( ! -d "$outputdir" );						#create dir if not already exist
         mkdir ("$outputdir/$switch_details{$key}{hostname}")             if( ! -d "$outputdir/$switch_details{$key}{hostname}" );		#create dir if not already exist
         mkdir ("$outputdir/$switch_details{$key}{hostname}/supportSave") if( ! -d "$outputdir/$switch_details{$key}{hostname}/supportSave" );	#create dir if not already exist
         system("chown -R $scpuser $outputdir");							#set the owner so the SCP user is able to write a file
         if( ! open( OUTPUT, "> $outputdir/$switch_details{$key}{hostname}/$file" ) ) {
            print STDERR "Cannot open file $outputdir/$switch_details{$key}{hostname}/$file because $!\n";
            next;
         }
         #
         # ssh into the switch and gather configuration information
         #
         print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
         open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd |") or warn "$!\n";
         while (<SSH>) {
            print OUTPUT; 										#print command output to filehandle
         }
         close SSH;
         #
         # The following is to remove the 'more' lines out of the output - not sure if we need this after migrating from telnet to ssh
         #
         #while( grep( /Type \<CR\>/, @output ) ) {
         #  @output= grep( ! /Type \<CR\>/, @output );
         #  push( @output, $telnet->cmd( "" ) );
         #}
         #print OUTPUT @output;										#print to output file
         #close( OUTPUT );										#close filehandle
      }													#end of forech loop
   }													#end of foreach loop
}													#end of subroutine




sub get_configupload {
   #
   print "running get_configupload subroutine \n" if ($verbose eq "yes");
   #
   #
   foreach $key (sort keys %switch_details) {                 						#loop through for each remote device
      # 
      # 
      $switch_details{$key}{configupload_filename} = "$outputdir/$switch_details{$key}{hostname}/configupload.$switch_details{$key}{hostname}";  #initialize value to avoid undef errors
      next if ( $switch_details{$key}{ping_status} eq "failed" );					#skip any devices that did not respond to ping
      next if ( $configupload eq "no");									#skip any devices if --configupload=no parameter was provided
      # 
      # Send the cfgUpload to an SCP server.  This is the file that will be used for disaster recovery.
      print "   running configUpload to send a copy of the $switch_details{$key}{hostname} config to $scpserver via SCP \n"; 
      $cmd = "";											#initialize variable in case we cannot determine the FabOS version
      # FabOS 5.x and 6.x and 7.x uses this syntax
      if ( ($switch_details{$key}{fabos_version} =~ /v5/) || ($switch_details{$key}{fabos_version} =~ /v6/) || ($switch_details{$key}{fabos_version} =~ /v7/) ) {
         $cmd = "configupload -p scp $scpserver,$scpuser,$switch_details{$key}{hostname}/configupload.$switch_details{$key}{hostname}";
      } 												#end of if block
      # FabOS 8.0 and 8.1 and 8.2.0 and 8.2.1 use the same syntax as 7.x 
      if ( ($switch_details{$key}{fabos_version} =~ /v8.0/) || ($switch_details{$key}{fabos_version} =~ /v8.1/) || ($switch_details{$key}{fabos_version} =~ /v8.2.0/) || ($switch_details{$key}{fabos_version} =~ /v8.2.1/) ) {
         $cmd = "configupload -all -p scp $scpserver,$scpuser,$switch_details{$key}{hostname}/configupload.$switch_details{$key}{hostname}";
      } 												#end of if block
      # FabOS 8.2.2 and later needs the -P 22 parameter to set the SCP/SFTP port number
      if ( ($switch_details{$key}{fabos_version} =~ /v8.2.2/) || ($switch_details{$key}{fabos_version} =~ /v9/) || ($switch_details{$key}{fabos_version} =~ /v10/) ) {
         $cmd = "configupload -all -P 22 -p scp $scpserver,$scpuser,$switch_details{$key}{hostname}/configupload.$switch_details{$key}{hostname}";
      } 												#end of if block
      print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
      open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or die "$!\n";
      while (<SSH>) {
         # nothing to read because we are just running a command on the switch
      }
      close SSH;
      #
      #
      # validate that the file has been sent via SCP from the Brocade switch to the local machine
      #
      print "   pausing for 60 seconds to give the configupload.$switch_details{$key}{hostname} file time to transfer over the network to backup server $localhost \n" if ($verbose eq "yes");
      sleep 60; 			
      if ( ! -e "$switch_details{$key}{configupload_filename}" ) {
         print STDERR "error - $switch_details{$key}{configupload_filename} was not created.  $! \n\n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $localhost:$0 error - $switch_details{$key}{configupload_filename} not created on SCP server $scpserver \n\n";
         print MAIL "The file $switch_details{$key}{configupload_filename} was not created on SCP server $scpserver.  Please investigate.\n\n";
      } 										#end of if block
      #
      # confirm that the configupload.$host file is less than 2 days old
      #
      if ( ! -e "$switch_details{$key}{configupload_filename}" ) {
         $now = time;									#get current time in seconds since the epoch
         #($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat("$outputdir/$switch_details{$key}{hostname}/configupload.$switch_details{$key}{hostname}");
         ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat("$switch_details{$key}{configupload_filename}");
	 $switch_details{$key}{configupload_filename_age_seconds} = $now-$mtime;			#age of file in seconds 
	 $switch_details{$key}{configupload_filename_age_days}    = $switch_details{$key}{configupload_filename_age_seconds}/60/60/24;     #convert seconds to days
	 $switch_details{$key}{configupload_filename_age_days}    = sprintf("%.0f",$switch_details{$key}{configupload_filename_age_days}); #truncate to zero decimal places, closest day is good enough
	 if ($mtime < ($now - 172800)) {	# 60 seconds x 60 minutes x 24 hours x 2 days = 172800
            print "WARNING: $switch_details{$key}{configupload_filename} is more than 2 days old.  Please investigate \n"; 
            open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
            print MAIL "From: $from\n";
            print MAIL "To: $to\n";
            print MAIL "Subject: $localhost:$0 script error.  $switch_details{$key}{configupload_filename}is obsolete \n\n";
            print MAIL "The $switch_details{$key}{configupload_filename} file did not get updated when the script was run.  Please investigate.\n\n";
            print MAIL "It may be that the SCP account $scpuser has expired or has been locked out.\n\n";
            close(MAIL);
         }												#end of if block
      }  												#end of if block
   }    												#end of foreach loop
}													#end of subroutine




sub get_supportsave {
   #
   print "running get_supportsave subroutine \n" if ($verbose eq "yes");
   #
   #
   foreach $key (sort keys %switch_details) {                 						#loop through for each remote device
      # 
      # 
      $switch_details{$key}{supportsave_filename_age_days} = 9999;					#initialize hash element with a ridiculously high number
      next if ( $switch_details{$key}{ping_status} eq "failed" );					#skip any devices that did not respond to ping
      # 
      # Send the supportSave to an SCP server.  This file may be requested by your next level of support for troubleshooting problems.
      #
      print "   Deleting old copy of supportSave data from SCP server \n";				#files are saved in hostname-S0-yyyymmddhhmm-*.gz format.
      opendir(DIR,"$outputdir/$switch_details{$key}{hostname}/supportSave") || die "Cannot open $outputdir/$switch_details{$key}{hostname}/supportSave : $!\n";
      @files = readdir(DIR); #get all filenames into an array
      close(DIR);
      foreach my $file(@files) {
         next if ( $file eq "\." );									#skip  . filename (aka current directory)
         next if ( $file eq "\.\." );									#skip .. filename (aka parent directory)
         next unless ( $file =~ /\.gz/ );								#skip any filenames without the .gz extension
         $now = time;											#get current time in seconds since the epoch
         ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat("$outputdir/$switch_details{$key}{hostname}/supportSave/$file");
	 if ($mtime < ($now - 172800)) {	# 60 seconds x 60 minutes x 24 hours x 2 days = 172800
            print "Deleting obsolete suportSave file $outputdir/$switch_details{$key}{hostname}/supportSave/$file \n";
            unlink("$outputdir/$switch_details{$key}{hostname}/supportSave/$file");
         }												#end of if block
      }													#end of foreach loop
      #
      # ssh into the switch and gather a supportSave
      # VERY ANNOYING NOTE: As of FabOS 7.x, the supportSave command requires a hardcoded SCP password, so we cannot use SSH key pairs
      # ANNOYANCE SOLVED: As of FabOS 9.x, the supportSave command no longer requires a hardcoded password, so we can finally use SSH key pairs
      #
      if ( $supportsave eq "yes" ) {									#skip if the --supportsave=no parameter was provided as a command line switch
         print "   running supportSave to collect RASLOG, TRACE, supportShow, core file, FFDC data, and send to $scpserver via SCP \n";
         print "   NOTE: This command can take up to 15 minutes to run - please be patient... \n";
         $cmd = "supportSave -n -u $scpuser -p $scppass -h $scpserver -d $switch_details{$key}{hostname}/supportSave -l scp";  #comment out line using -p $scppass, now using SSH key pair auth
	 $cmd = "supportSave -n -u $scpuser -h $scpserver -d $switch_details{$key}{hostname}/supportSave -l scp";
         print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
         open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or die "$!\n";
         while (<SSH>) {
         # nothing to read because we are just running a command on the switch
         }												#end of while loop
      }													#end of if block
      # 
      # Confirm a recent supportSave exists (less than 2 weeks old)
      #
      print "   confirming recent supportSave files exist \n";						#files are saved in hostname-S0-yyyymmddhhmm-*.gz format.
      opendir(DIR,"$outputdir/$switch_details{$key}{hostname}/supportSave") || die "Cannot open $outputdir/$switch_details{$key}{hostname}/supportSave : $!\n";
      @files = readdir(DIR); #get all filenames into an array
      close(DIR);
      foreach my $file(@files) {
         next if ( $file eq "\." );									#skip  . filename (aka current directory)
         next if ( $file eq "\.\." );									#skip .. filename (aka parent directory)
         next unless ( $file =~ /\.gz/ );								#skip any filenames without the .gz extension
         $now = time;											#get current time in seconds since the epoch
         ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat("$outputdir/$switch_details{$key}{hostname}/supportSave/$file");
	 $switch_details{$key}{supportsave_filename_age_seconds} = $now-$mtime;				#age of file in seconds 
	 $switch_details{$key}{supportsave_filename_age_days}    = $switch_details{$key}{supportsave_filename_age_seconds}/60/60/24; #convert seconds to days
	 $switch_details{$key}{supportsave_filename_age_days}    = sprintf("%.0f",$switch_details{$key}{supportsave_filename_age_days}); #truncate to zero decimal places, closest day is good enough
         print "   age of file $outputdir/$switch_details{$key}{hostname}/supportSave/$file is $switch_details{$key}{supportsave_filename_age_days} days \n" if ($verbose eq "yes");
      }													#end of foreach loop
      close SSH;											#close filehandle
   } 													#end of foreach loop
}													#end of subroutine




sub check_error_log {
   #
   print "running check_error_log subroutine \n" if ($verbose eq "yes");
   #
   #
   foreach $key (sort keys %switch_details) {                 						#loop through for each remote device
      # 
      # 
      next if ( $switch_details{$key}{ping_status} eq "failed" );					#skip any devices that did not respond to ping
      # 
      # Check the switch error log for segmented fabrics, zone conflicts, etc.
      $switch_details{$key}{errlog}{zoneconflict} = 0;							#initialize counter variable for each hostname
      $switch_details{$key}{errlog}{failedlogin}  = 0;							#initialize counter variable for each hostname
      $switch_details{$key}{errlog}{domainid}     = 0;							#initialize counter variable for each hostname
      $switch_details{$key}{errlog}{hitemp}       = 0;							#initialize counter variable for each hostname
      $switch_details{$key}{errlog}{overall}      = "unknown";						#initialize hash element for overall status of error log
      #
      print "Checking switch error log \n"; 
      $cmd = "errdump";
      print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
      open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or warn "$!\n";
      while (<SSH>) {
        if ( /Zone Conflict/ ) {									#look for "Zone Conflict" entries in error log
            $switch_details{$key}{errlog}{zoneconflict}++;						#increment counter
         }												#end of if block
         #
         if ( /Security violation: Login failure attempt/ ) {						#look for "Security violation" entries in error log
            $switch_details{$key}{errlog}{failedlogin}++;						#increment counter
         }												#end of if block
         #
         if ( /domain IDs overlap/ ) {									#look for "domain IDs overlap" entries in error log
            $switch_details{$key}{errlog}{domainid}++;							#increment counter
         }												#end of if block
         #
         if ( /High temperature/ ) {									#look for "domain IDs overlap" entries in error log
            $switch_details{$key}{errlog}{hitemp}++;							#increment counter
         }												#end of if block
      } 												#end of while loop
      close SSH;
      #
      # Set an overall "ok" or "not ok" status for the error log
      # We yse this ok/notok flag to set green/red colors in the report outpout
      $switch_details{$key}{errlog}{overall} = "ok";							#initialize variable
      $switch_details{$key}{errlog}{overall} = "not ok" if ($switch_details{$key}{errlog}{zoneconflict} >  0);	#indicate a problem 
      $switch_details{$key}{errlog}{overall} = "not ok" if ($switch_details{$key}{errlog}{failedlogin}  > 20);	#indicate a problem 
      $switch_details{$key}{errlog}{overall} = "not ok" if ($switch_details{$key}{errlog}{domainid}     >  0);	#indicate a problem 
      $switch_details{$key}{errlog}{overall} = "not ok" if ($switch_details{$key}{errlog}{hitemp}       >  0);	#indicate a problem 
      #
      #
      #
      # Now that the entire error log has been reviewed, send alerts for any problems found.
      # The alert is sent here because we have now counted up the number of each error message.
      #
      if ( $errlog_failedlogin > 20 ) {				#only send alert if there are more than 20 errors
         print STDERR "\n\nERROR - found $errlog_failedlogin Login failures in error log.  Run \"errdump\" command on fibre switch for more details. \n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $switch_details{$key}{hostname} error - Login failures detected \n\n";
         print MAIL "This message was generated by the $localhost:$0 script.\n";
         print MAIL "There were $errlog_failedlogin login failures detected on the $switch_details{$key}{hostname} Brocade fibre switch.\n\n";
         print MAIL "This might just be a legitimate sysadmin making a typo, or it may be a breakin attempt.\n\n";
         print MAIL "Please login to the fibre switch and review the error log from the GUI, \n";
         print MAIL "or use the \"errdump\" or \"errshow\" commands from the CLI.\n\n";
         print MAIL "Please clear the error log when you are done with the \"errclear\" command.\n\n";
         print MAIL "If you do not remember to clear the error log, you may get multiple email alerts like this one.\n\n";
      }								#end of if block
      if ( $errlog_zoneconflict > 0 ) {				#only send alert if there are more than zero errors
         print STDERR "\n\nERROR - found Zone Conflict in error log.  Run \"errdump\" command on fibre switch for more details. \n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $switch_details{$key}{hostname} error - Zone Conflict detected \n\n";
         print MAIL "This message was generated by the $localhost:$0 script.\n";
         print MAIL "There were $errlog_zoneconflict Zone Conflict messages detected in the error log on the $switch_details{$key}{hostname} Brocade fibre switch.\n";
         print MAIL "This probably means that the switches in this fabric have been segmented, which may result in hosts losing access to their SAN disk.\n\n";
         print MAIL "Please clear the error log when you are done with the \"errclear\" command.\n\n";
         print MAIL "If you do not remember to clear the error log, you may get multiple email alerts like this one.\n\n";
         print MAIL "Please login to the fibre switch and review the error log from the GUI, \n";
         print MAIL "or use the \"errdump\" or \"errshow\" commands from the CLI.\n\n";
         print MAIL "TROUBLESHOOTING TIPS: \n";
         print MAIL "--------------------- \n";
         print MAIL "1. Ensure you have a good backup of the switch config via the configUpload command. \n";
         print MAIL "2. Confirm there are no duplicate domain ID values if there are multiple switches in the fabric. \n";
         print MAIL "3. If there are multiple switches in the fabric, try deleting the zoning configs from one switch, \n";
         print MAIL "   then let it try to re-join the fabric by merging in the zoning config from the other switch. \n";
         print MAIL "   (use cfgdelete, cfgsave, reboot) \n\n";
      } 							#end of if block
      if ( $errlog_domainid > 0 ) {				#only send alert if there are more than zero errors
         print STDERR "\n\nERROR - found overlapping domain ID values in fibre switch fabric.  Run \"errdump\" command on fibre switch for more details. \n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $switch_details{$key}{hostname} error - found overlapping domain ID values in fibre switch fabric \n\n";
         print MAIL "This message was generated by the $localhost:$0 script.\n";
         print MAIL "There were $errlog_domainid Overlapping domain ID messages found in the error log on the $switch_details{$key}{hostname} Brocade fibre switch.\n\n";
         print MAIL "This usually indicates the multiple fibre switches in the same fabric have the same domain ID.\n";
         print MAIL "This probably means that the switches in this fabric have been segmented, which may result in hosts losing access to their SAN disk.\n\n";
         print MAIL "Please login to the fibre switch and review the error log from the GUI, \n";
         print MAIL "or use the \"errdump\" or \"errshow\" commands from the CLI.\n\n";
         print MAIL "Please clear the error log when you are done with the \"errclear\" command.\n\n";
         print MAIL "If you do not remember to clear the error log, you may get multiple email alerts like this one.\n\n";
         print MAIL "TROUBLESHOOTING TIPS: \n";
         print MAIL "--------------------- \n";
         print MAIL "1. To change the domain ID on a fibre switch, a brief outage will be required.  Ensure fabric redundancy is in place before proceeding.\n";
         print MAIL "2. To change the domain ID on a fibre switch from the GUI, click Switch Admin, Switch, Disable, Apply, change the domain ID to a unique value, Enable, Apply.\n";
         print MAIL "3. If you prefer to use the CLI instead of the GUI, the commands are: \n";
         print MAIL "      switchdisable \n";
         print MAIL "      configure    (change the domain ID but leave everything else the same) \n";
         print MAIL "      switchenable \n";
         print MAIL "      errclear     (this clears the error log)\n";
         print MAIL "      reboot       (this reboots the switch) \n\n";
      }								#end of if block
      if ( $errlog_hitemp > 0 ) {				#only send alert if there are more than zero errors
         print STDERR "\n\nERROR - found $errlog_hitemp High temperature warnings in error log.  Run \"errdump\" command on fibre switch for more details. \n";
         open(MAIL, "|$sendmail -oi -t") or warn "Cannot open pipe to sendmail for sending report $! \n";
         print MAIL "From: $from\n";
         print MAIL "To: $to\n";
         print MAIL "Subject: $switch_details{$key}{hostname} error - high temperature warnings in error log \n\n";
         print MAIL "This message was generated by the $localhost:$0 script.\n";
         print MAIL "There were $errlog_hitemp High temperature warnings found in the error log on the $switch_details{$key}{hostname} Brocade fibre switch.\n\n";
         print MAIL "This may indicate problems with the cooling system or environmental controls.\n\n";
         print MAIL "Please login to the fibre switch and review the error log from the GUI, \n";
         print MAIL "or use the \"errdump\" or \"errshow\" commands from the CLI.\n\n";
         print MAIL "Please clear the error log when you are done with the \"errclear\" command.\n\n";
         print MAIL "If you do not remember to clear the error log, you may get multiple email alerts like this one.\n\n";
      }													#end of if block
   }													#end of foreach loop
}													#end of subroutine




sub set_time {
   #
   print "running set_time subroutine \n" if ($verbose eq "yes");
   #
   # This subroutine is used en environments where the Brocade switches do not have access to NTP servers for time synchronization
   #
   foreach $key (sort keys %switch_details) {                 						#loop through for each remote device
      # 
      next if ( $switch_details{$key}{ping_status} eq "failed" );					#skip any devices that did not respond to ping
      # 
      #  Check to see NTP server(s) are defined.
      #  Sample output: 
      #     sansw01:> tsclockserver
      #        Active NTP Server           LOCL     <--- indicates no NTP servers defined
      #        Configured NTP Server List  LOCL
      #
      #     sansw02:> tsclockserver
      #        Active NTP Server           192.168.1.4               <--- NTP server used for most recent time sync
      #        Configured NTP Server List  192.l68.1.4;192.168.1.5   <--- list of defined NTP servers
      #
      #     sansw03:> tsclockserver
      #        Active NTP Server           time.example.com               <--- NTP server used for most recent time sync
      #        Configured NTP Server List  time.example.com;pool.ntp.org  <--- list of defined NTP servers
      #
      $switch_details{$key}{tsClockServer} = "unknown";							#initialize hash element
      print "Checking NTP server settings \n"; 
      $cmd = "tsClockServer";
      print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
      open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or warn "$!\n";
      while (<SSH>) {
        s/\t/ /g;											#replace tab characters with spaces to make regex simpler
        if ( /Active NTP Server +([a-zA-Z0-9_\-\.]+)/ ) {						#look for the line that shows the currently used NTP server, capture hostname or IP address
            $switch_details{$key}{tsClockServer} = $1;							#set hash element to LoCAL, which means use the local hardware clock
         }												#end of if block
        if ( /Active NTP Server +LOCL/ ) {								#look for the line that shows the currently used NTP server
            $switch_details{$key}{tsClockServer} = $1;							#set hash element to LoCAL, which means use the local hardware clock
         }												#end of if block
      } 												#end of while loop
      close SSH;											#close filehandle
      print "   found NTP server: $switch_details{$key}{tsClockServer} \n" if ($verbose eq "yes");
      #
      # Get the time zone
      # Sample ouput:
      #    sansw01:> tsTimeZone
      #    US/Mountain               <---- modern style of output for FabOS 7.x
      #    America/Edmonton          <---- modern style of output for FabOS 7.x
      #
      #    sansw01:> tsTimeZone
      #    -8,0                      <---- older style of output, shows offset from UTC in hours,minutes.  Negative numbers are behind UTC.
      #     3,0                      <---- older style of output, shows offset from UTC in hours,minutse   Positive numbers are ahead of UTC.
      #
      $switch_details{$key}{tsTimeZone} = "unknown";							#initialize hash element
      print "Checking time zone settings \n"; 
      $cmd = "tsTimeZone";
      print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
      open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or warn "$!\n";
      while (<SSH>) {
        if ( /([A-Za-z]+\/[A-Za-z]+)/ ) {								#look for output in US/Mountain or America/Edmonton format
            $switch_details{$key}{tsTimeZone} = $1;							#set hash element
         }												#end of if block
        if ( /(^\-[0-9]+,[0-9]++)/ ) {									#look for output in -8,0 format (negative offset from UTC)
            $switch_details{$key}{tsTimeZone} = $1;							#set hash element
         }												#end of if block
        if ( /(^[0-9]+,[0-9]++)/ ) {									#look for output in 3,0 format (positive offset from UTC)
            $switch_details{$key}{tsTimeZone} = $1;							#set hash element
         }												#end of if block
      } 												#end of while loop
      close SSH;											#close filehandle
      print "   found time zone: $switch_details{$key}{tsTimeZone} \n" if ($verbose eq "yes");
      #
      # If the Brocade switch does not have a defined NTP server, set the time to prevent the clock from drifting too far out of sync.
      # This does not kepp the time exact to the millisecond, but assuming backup script runs weekly, it should keep the time accurate to the minute.
      #
      next unless ( $switch_details{$key}{tsClockServer} eq "LOCL" );					#skip to next device if NTP server is defined
      # figure out the current time  in seconds since the epoch (Jan 1, 1980)
      ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time);
      $year = ($year + 1900); 										# $year is years since 1900
      $year = sprintf("%02d", $year % 100);								# Brocade switch only wants the last 2 digits of the year
      $mon  = ($mon + 1);										# $mon starts counting at zero
      $mon  = "0$mon"  if ( length($mon)  < 2 );							# pad month with leading zero if necessary
      $mday = "0$mday" if ( length($mday) < 2 );							# pad day of month with leading zero if necessary
      $hour = "0$hour" if ( length($hour) < 2 );							# pad hour         with leading zero if necessary
      $min  = "0$min"  if ( length($min)  < 2 );							# pad minute       with leading zero if necessary
      # adjust for timezone offset between the Brocade switch and the local machine
      $hour = $hour+0 if ( $switch_details{$key}{hostname} =~ "san-hq-[0-9]+");				#switch hostnames san-hq-##          are same timezone as local machine
      $hour = $hour+0 if ( $switch_details{$key}{hostname} =~ "san-uat-[0-9]+");			#switch hostnames san-uat-##         are same timezone as local machine
      $hour = $hour+0 if ( $switch_details{$key}{hostname} =~ "san-colo-[0-9]+");			#switch hostnames san-cole-##        are same timezone as local machine
      $hour = $hour+1 if ( $switch_details{$key}{hostname} =~ "ibm-san-caw-[0-9]+");			#switch hostnames ibm-san-caw-##     are 1 hours later than local machine
      $hour = $hour+1 if ( $switch_details{$key}{hostname} =~ "ibm-san-uat-caw-[0-9]+");		#switch hostnames ibm-san-uat-caw-## are 1 hours later than local machine
      $hour = $hour+3 if ( $switch_details{$key}{hostname} =~ "ibm-san-cae-[0-9]+");			#switch hostnames ibm-san-cae-##     are 3 hours later than local machine
      #set the time on the Brocade switc
      print "   setting time in mmddHHMMyy format to $mon$mday$hour$min$year \n" if ($verbose eq "yes"); 
      $cmd = "date \"$mon$mday$hour$min$year\"";
      print "   running $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
      open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or warn "$!\n";
      close SSH;											#close filehandle
      #
      # This section sets the timezone on the remove devices.  This section only runs if NTP is not in use.
      #
      $cmd = "tsTimeZone";										#default command, no timezone specified, will show timezone instead of setting timezone
      $cmd = "tsTimeZone \"US/Pacific\""  if ( $switch_details{$key}{hostname} =~ "san-hq-[0-9]+");	#switch hostnames san-hq-##          are in timezone US/Pacific
      $cmd = "tsTimeZone \"US/Pacific\""  if ( $switch_details{$key}{hostname} =~ "san-uat-[0-9]+");	#switch hostnames san-uat-##         are in timezone US/Pacific
      $cmd = "tsTimeZone \"US/Pacific\""  if ( $switch_details{$key}{hostname} =~ "san-colo-[0-9]+");	#switch hostnames san-colo-##        are in timezone US/Pacific
      $cmd = "tsTimeZone \"US/Mountain\"" if ( $switch_details{$key}{hostname} =~ "ibm-san-caw-");	#switch hostnames ibm-san-caw-##     are in timezone US/Mountain
      $cmd = "tsTimeZone \"US/Mountain\"" if ( $switch_details{$key}{hostname} =~ "ibm-san-uat-caw-");	#switch hostnames ibm-san-uat-caw-## are in timezone US/Mountain
      $cmd = "tsTimeZone \"US/Eastern\""  if ( $switch_details{$key}{hostname} =~ "ibm-san-cae-");	#switch hostnames ibm-san-cae-##     are in timezone US/Eastern
      print "   running command to set timezone: $ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd \n" if ($verbose eq "yes");
      open(SSH,"$ssh $brocade_userid\@$switch_details{$key}{hostname} $cmd  |") or warn "$!\n";
      close SSH;											#close filehandle
   }													#end of foreach loop
}													#end of subroutine




sub generate_readme {
   #
   print "running generate_readme subroutine \n" if ($verbose eq "yes");
   #
   # Generate a readme file that explains how to restore configs in the event of a disaster
   #
   print "   generating a readme file at $readme \n";
   open (README,">$readme") or warn "ERROR: Could not open $readme for writing $! \n";
   print README "This directory contains backups of the Brocade fibre switches. \n\n";
   print README "These backups are created by the $0 script that runs from a cron job on $localhost. \n\n";
   print README "There is one subdirectory for each backed up Brocade switch.  You should validate that \n";
   print README "all switches in the environment are listed here.\n\n";
   print README "Most of the files you find in each subdir are the output of commands run on each switch to \n";
   print README "show you specific configuration parameters.  These files can be used for troubleshooting. \n\n";
   print README "In the event of a disaster, you can restore a backed-up configuration with this procedure:\n";
   print README "   1) Get the Brocade switch on the network.  Use a null modem cable in the serial port if necessary.\n";
   print README "      You may need to use the \"ipaddrset\" command on the switch to set the IP address.\n";
   print README "   2) Use the \"configDownload\" command on the Brocade switch to download from: \n";
   print README "         scp://$scpserver:$outputdir/hostname/configupload.hostname \n";
   print README "   3) Reboot the brocade switch with the \"switchreboot\" command.\n";
   print README "   4) Verify that the switch comes back online.\n";
   print README "   5) Verify that the disk paths provided by that switch are working again.\n";
   print README "   6) Confirm DNS config information is correct with: dnsConfig --show \n";
   print README "   7) Confirm SNMP configuration is correct with: snmpConfig --show snmpv1 \n";
   print README "   8) Confirm \"backup\" userid exists with: userConfig --show backup \n";
   print README "   9) The SSH host key may have changed if there was a hardware replacement, confirm this backup script can automatically login to the new switch. \n";
   print README "   10) If required, re-run the SSH key setup process described in this script for setting up a new switch \n";
   close README;											#close filehandle
}													#end of subroutine






sub generate_html_report {
   #
   print "running generate_html_report subroutine \n" if ($verbose eq "yes");
   #
   # Generate a report for the sysadmin that shows which switches have been backed up
   #
   print "Generating a report for the sysadmin \n";
   #
   print "   opening $output_file for writing \n" if ($verbose eq "yes");
   open (OUT,">$output_file") or die "Cannot open $output_file for writing: $! \n";
   print OUT "<html><head><title>Brocade switch backup report</title></head><body> \n";
   print OUT "<p>This report is generated by the $0 script on $scpserver </p> \n";
   print OUT "<p>Please review this report to ensure that all the Brocade fibre channel switches are getting backed up on a regular basis.\n";
   print OUT "<p>Backups less than a week old are shown in <font color=green> green </font>, missing or obsolete backups are shown in <font color=red> red </font>.\n\n";
   print OUT "<p> the event of a disaster, you can recover a Brocade switch config by using the configDownload command to retrieve a backed up configupload.hostname file from $scpserver:$outputdir/hostname/configupload.hostname .\n\n";
   print OUT "<p><table border=1><tr bgcolor=gray><td>Hostname <td> Backup Filename <td> bytes <td> Backup Date <td> ping <td> errlog <td> supportSave <td> in DNS? <td> DNS1 <td> DNS2 <td> NTP <td> FabOS \n"; 
   # 
   foreach $key (sort keys %switch_details) {                 												#loop through for each remote device
      # 
      # print the hostname to the HTML table
      # 
      print OUT "<tr><td> $switch_details{$key}{hostname} ";
      # 
      #
      # get the details of each backup file
      #
      if ( ! -f "$switch_details{$key}{configupload_filename}" ) {											#run this section if the backup file does not exist
         print OUT "<td bgcolor=red> no backup file found <td> <td> \n";
      }  																		# end of if block
      if ( -f "$switch_details{$key}{configupload_filename}" ) {											#check to see if the config backup file exists
         # 
         # print the backup filename to the HTML table
         # 
         $switch_details{$key}{configupload_filename_shortened} = $switch_details{$key}{configupload_filename};						# including the full path to the filename makes the report hard to read on
         $switch_details{$key}{configupload_filename_shortened} =~ s/^\/.*\///g; 									# mobile devices, so cut out the leading path
         print OUT "<td> $switch_details{$key}{configupload_filename_shortened} ";
         # 
         # get the time/date stamp of the backup file
         ($dev,$ino,$mode,$nlink,$uid,$gid,$rdev,$size,$atime,$mtime,$ctime,$blksize,$blocks) = stat("$switch_details{$key}{configupload_filename}");
         # $mtime is last modification time since the epoch (Jan 1, 1970) 
         # Let's change that to a human-friendly date stamp
         ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime($mtime);
         $year = ($year + 1900);															# $year is years since 1900
         $mon  = ($mon  + 1);																# $mon starts counting at zero
         $mon  = "0$mon"  if ( length($mon)  < 2 );													# pad month with leading zero if necessary
         $mday = "0$mday" if ( length($mday) < 2 );													# pad day of month with leading zero if necessary
         $now = time;                                                                									# get current time in seconds since the epoch
         # 
         # print the backup file size the HTML table
         print OUT "<td> $size ";
         # 
         # print the backup date to the HTML table
         $bgcolor = "white";																# default color
         $bgcolor = "green" if ($mtime >  ($now - 691200));        											# 60 seconds x 60 minutes x 24 hours x 8 days = 691200
         $bgcolor = "red"   if ($mtime <= ($now - 691200));        											# 60 seconds x 60 minutes x 24 hours x 8 days = 691200
         print OUT "<td bgcolor=$bgcolor> $year/$mon/$mday ";
      }																			#end of if block
      # 
      # print the ping reply status from the backup server to the Brocade switch to the HTML table
      # 
      $bgcolor = "white";										  						# default color
      if ( $switch_details{$key}{ping_status} eq "ok") { print OUT "<td bgcolor=green> ping ok 	"} 					  		# ping to Brocade switch was successfull
      if ( $switch_details{$key}{ping_status} ne "ok") { print OUT "<td bgcolor=red>   ping fail"}  							# ping to Brocade switch failed
      # 
      # print the status of the error log to the HTML table
      # 
      $bgcolor = "white";									  							# default color
      if ( $switch_details{$key}{errlog}{overall} eq "ok") { print OUT "<td bgcolor=green> ok "}    							# no problems in error log
      if ( $switch_details{$key}{errlog}{overall} ne "ok") { 
         print OUT "<td bgcolor=red>errors:";
         print OUT "<br> Zone conflict"           if ( $switch_details{$key}{errlog}{zoneconflict} >  0 ) ;
         print OUT "<br> Excessive failed logins" if ( $switch_details{$key}{errlog}{failedlogin}  > 20 ) ;
         print OUT "<br> Domain ID conflict"      if ( $switch_details{$key}{errlog}{domainid}     >  0 ) ;
         print OUT "<br> High temperature alert"  if ( $switch_details{$key}{errlog}{hitemp}       >  0 ) ;
      }   																		#end of if block
      # 
      # print the status of the last supportSave error log to the HTML table
      # 
      $bgcolor = "white";																# default color
      print "   $switch_details{$key}{hostname} supportsave_filename_age_days:$switch_details{$key}{supportsave_filename_age_days} \n" if ($verbose eq "yes");
      if ( $switch_details{$key}{supportsave_filename_age_days} < 14 ) { 										#most recent supportSave is less than 14 days old
         print OUT "<td bgcolor=green> ok ";
      } else { 
         print OUT "<td bgcolor=red> please check ";
      } 																		#end of if/else block
      # 
      # print the status of the Brocade switch having valid name resolution defined in DNS 
      # 
      $switch_details{$key}{nslookup_status} = "" if (!defined($switch_details{$key}{nslookup_status}));						#initialize to avoid undef error
      $bgcolor = "green" if ( $switch_details{$key}{nslookup_status} eq "ok");										#Brocade switch hostname is     defined in DNS
      $bgcolor = "red"   if ( $switch_details{$key}{nslookup_status} ne "ok");										#Brocade switch hostname is not defined in DNS
      print OUT "<td bgcolor=$bgcolor> $switch_details{$key}{nslookup_status}";    	
      # 
      # print the status of the ping check to the DNS1 server 
      # 
      $switch_details{$key}{nameserver1} = "" if (!defined($switch_details{$key}{nameserver1}));							#initialize to avoid undef error
      if ( $switch_details{$key}{nameserver1_ping_status} eq "ok") { print OUT "<td bgcolor=green> $switch_details{$key}{nameserver1} ping ok "}    	#ping was successful to nameserver1
      if ( $switch_details{$key}{nameserver1_ping_status} ne "ok") { print OUT "<td bgcolor=red>   $switch_details{$key}{nameserver1} ping fail"}    	#ping failed         to nameserver1
      # 
      # print the status of the ping check to the DNS2 server 
      # 
      $switch_details{$key}{nameserver2} = "" if (!defined($switch_details{$key}{nameserver2}));							#initialize to avoid undef error
      if ( $switch_details{$key}{nameserver2_ping_status} eq "ok") { print OUT "<td bgcolor=green> $switch_details{$key}{nameserver2} ping ok "}    	#ping was successful to nameserver2
      if ( $switch_details{$key}{nameserver2_ping_status} ne "ok") { print OUT "<td bgcolor=red>   $switch_details{$key}{nameserver2} ping fail"}    	#ping failed         to nameserver2
      # 
      # print the hostname/IP of the active NTP server
      # 
      $switch_details{$key}{tsClockServer} = "" if (!defined($switch_details{$key}{tsClockServer}));							#initialize to avoid undef error
      if ( $switch_details{$key}{tsClockServer} eq "LOCL") { print OUT "<td bgcolor=white> $switch_details{$key}{tsClockServer}" }    			#no external NTP defined, using local hardware clock
      if ( $switch_details{$key}{tsClockServer} ne "LOCL") { print OUT "<td bgcolor=green> $switch_details{$key}{tsClockServer}" }    			#external NTP defined
      # 
      # print the FabOS version
      # 
      $switch_details{$key}{fabos_version} = "unknown" if (!defined($switch_details{$key}{fabos_version}));						#initialize to avoid undef error
      if ( $switch_details{$key}{tsClockServer} eq "unknown") { print OUT "<td bgcolor=orange> $switch_details{$key}{fabos_version}" }  		
      if ( $switch_details{$key}{tsClockServer} ne "unknown") { print OUT "<td bgcolor=green>  $switch_details{$key}{fabos_version}" }   		
      # 
      print OUT "\n";																	#linefeed at end of each table row
   }																			#end of foreach loop
   print OUT "</table></body></html> \n";														#print HTML footer
}																			#end of subroutine





sub send_report_via_email {
   #
   print "running send_report_via_email subroutine \n" if ($verbose eq "yes");
   # 
   return if ( $report eq "no");									#break out of subroutine if --report=no parameter was provided
   open(MAIL,"|$sendmail -t");
   # Mail Header
   print MAIL "To: $to\n";
   print MAIL "From: $from\n";
   print MAIL "Subject: $subject\n";
   # Mail Body
   print MAIL "Content-Type: text/html; charset=ISO-8859-1\n\n";					#tell mail client to render output as HTML
   open (IN,"$output_file") or warn "Cannot open $output_file for reading: $! \n";
   while (<IN>) {                               							#read a line from the filehandle
      print MAIL $_;                            							#print to email message
   }                                            							#end of while loop
   close IN;                                    							#close filehandle
   close MAIL;                                  							#close filehandle
}                                               							#end of subroutine




#
# --  Main body of script  -------------------------------------------------
#
get_options;
sanity_checks;
read_config_file;
build_hash;
check_name_resolution;
ping_brocade_switch;
get_fabos_version;
get_dns_servers;
ping_dns_servers;
get_config_details;
get_configupload;
get_supportsave;
check_error_log;
set_time;
generate_readme;
generate_html_report;
send_report_via_email;


