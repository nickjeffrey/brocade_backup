# brocade_backup
script to backup configs on Brocade Fibre Channel switches

# Notes

 This script will pull the configuration information from a Brocade fibre switch and dump them into a directory on a UNIX host where they will get backed up to tape during the regular filesystem backups.

# Create user account on UNIX box

Create a low privilege user account on the UNIX box that will be used to run this perl script and hold the Brocade config backups.

Example userid creation for AIX:
```
     mkuser -a id=30007 maxage=0 home=/home/brocade brocade
     passwd brocade
     pwdadm -c brocade
     echo Creating SSH key pair for brocade user
     su - brocade
     ssh-keygen 
```

Example userid creation for Linux:
```
     useradd --uid=30007 --home-dir=/home/brocade brocade
     passwd brocade
     echo Creating SSH key pair for brocade user
     su - brocade
     ssh-keygen 
```

# Download files
Download the .pl and .cfg files to /home/brocade/ on the UNIX box

# Edit config file
Please edit the ```/home/brocade/brocade_backup.cfg``` file to match your site-specific details.  A sample is shown below:
```
    #
    # email address details 
    #
    to=janedoe@example.com,helpdesk@example.com
    from=alerts@example.com
    subject=Brocade switch backup report

    #
    # SCP server that Brocade switches send backups to
    #
    scpserver=server01.example.com
    scpuser=brocade
    scppass=SomeSecretPassword
    
    
    # 
    # Brocade switches to be backed up
    #
    host=sansw01,sansw02,10.20.30.41,10.20.30.42
```



# Create cron job on UNIX box
This script is configured to run from a cron job on a UNIX box 

This script is run from the crontab of the brocade userid

If you have multiple backup servers, just stagger the backups by an hour so we have backups at multiple sites

```  45 4 * * 1 /home/brocade/brocade_backup.pl >/dev/null 2>&1    #backup Brocade configs Mondays at 04:45 ```


# Create user account on Brocade switches

You will need an identical userid/password on all the Brocade fibre switches.  The following example shows how to create a userid called "backup" with a role of "admin" and a descriptive message.  It would be nice if we could just create a user with the "operator" role, but we need the "admin" role to run the configUpload command.
```
    ssh <switchname>
    userid: admin
    password: ******
    userConfig --add backup -d "used by automated scripts" -r admin -c admin -l 1-128
    sshutil allowuser backup
    sshutil importpubkey
       Enter user name for whom key is imported:backup
       Enter IP address:165.89.12.156  # remote host ip
       Enter remote directory:/home/brocade/.ssh
       Enter public key name(must have .pub suffix):id_rsa.pub
       Enter login name:brocade
       Password: brocade_user_password_on_unix_box
       public key is imported successfully.
    exit
```

We also want the Brocade switch to ssh into a remote UNIX host without a password so we can run the configUpload and supportSave commands without entering a password.

This means we will want to generate public/private keys on the Brocade switch and put the public key on the remote UNIX box.
```
    ssh <switchname>
    userid: backup
    password: *****
    sshutil genkey -rsa
    sshutil exportpubkey
       Enter IP address: 192.168.38.244 #remote host IP
       Enter remote directory:/home/brocade/.ssh
       Enter login name:brocade
       Password:SomeSuperSecretPassword
       public key out_going.pub is exported successfully
    exit
```

Now the public key has been saved as unixbox:/home/brocade/.ssh/out_going.pub

You will need to append this public key to the authorized_keys file on the UNIX box.
```
     $ hostname
       unixbox
     $ whoami
       brocade
     $ cat /home/brocade/.ssh/out_going.pub >> /home/brocade/.ssh/authorized_keys
     $ chmod 600 /home/brocade/.ssh/authorized_keys
```

# Assumptions

 It is assumed that this script is being run on a UNIX-like server with a running SSH/SCP daemon.  This script has been tested on AIX and Linux, other UNIX flavours are expected to work.  

When running the "configUpload" command on each Brocade switch, a copy of the switch config will be sent via SCP

It is assumed that a user account on the SCP server exists (because this script chown's to that user)




# Troubleshooting
- Confirm you can ssh into the switch with the $ssh_userid and $password in this script
- Confirm you can SCP into $scpserver with $scpuser / $scppass 
- Confirm the directory on the SCP server that the files are sent to is owned by $scpuser
- Confirm there are no firewalls preventing the SSH traffic used by this script
- Confirm that ssh has not been disabled on any of the Brocade switches
- Confirm the $userid on the Brocade switch has the "admin" role, which is required to run configupload
- Confirm each brocade switch can perform name resolution to get the IP of the SCP server with the dnsconfig command
- Confirm that all brocade switches in your environment are listed in the @hostname array 
- Confirm this script is running from the SCP server, because we check the local filesystem for the configupload file
- Confirm that $scpuser exists in /etc/passwd on the system this script runs from 
- Confirm that $scpuser does not have an expired password (try to SCP or SSH in manually to confirm) 
- Confirm the host you are running this script from can query a DNS server for name resolution (check /etc/resolv.conf)
- Confirm SSH works in *both* directions.  There might be firewalls that only allow SSH in one direction.


# Restore Procedure
In the event that a Brocade switch is lost/destroyed/corrupted, and you want to restore the backed up version of the config, you can use this procedure:
- Get the switch on the network 
- ssh into the switch
- Use the "ConfigDownload" command to download the switchname.config.txt file that was backed up
- Running the "ConfigDownload" command will restore the zone configs, but will not re-create any user accounts, DNS configuration, SNMP configuration, SSH keys.

# Sample email report 

You will receive an email report that looks similar to the following:

```
From: alerts@example.com
Sent: Tuesday, January 3, 2023 1:34 PM
To: Jane.Doe@example.com
Subject: Brocade switch backup report

This report is generated by the ./test.pl script on server01.example.com
Please review this report to ensure that all the Brocade fibre channel switches are getting backed up on a regular basis. 
Backups less than a week old are shown in green , missing or obsolete backups are shown in red . 
the event of a disaster, you can recover a Brocade switch config by using the configDownload command to retrieve a backed up configupload.hostname file from server01.example.com:/home/brocade/hostname/configupload.hostname . 
```
<img src=images/report1.png>
