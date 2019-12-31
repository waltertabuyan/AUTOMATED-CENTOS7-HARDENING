#!/bin/bash
## LINUX HARDENNING SCRIPT ##
## CENTOS 7 LINUX ##

##############################
## Special Command shortcut ##
##############################
pow=sudo

###########################
## Systems Engineer Name ##
###########################
s1=santy.rafol
s2=brando.caldetera
s3=walter.alcantara
s4=crispin.parungao
s5=jack.ogania
s6=eugene.duguran
s7=philip.destura
s8=yoeh.delosreyes
s9=ishmael.cuyson
g1=wheel
g2=ogadmin
g3=ogsys
g4=ogdev

############################
## Sudoers Configurations ##
############################
$pow yum -y install vim
$pow cd /root/automated-centos7-hardening/
$pow mv -f /root/automated-centos7-hardening/sudoers /etc/


#################################
## Command Log User Log Rotate ##
#################################
$pow cat /root/automated-centos7-hardening/commands.txt >> /etc/bashrc
$pow cat > /etc/rsyslog.d/commands.conf <<- _EOF_ 
local6.*    /var/log/commands.log
_EOF_
$pow systemctl restart rsyslog 
$pow cat > /root/syslog <<- _EOF_ 
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
/var/log/commands.log
{
    daily
    rotate 45
    compress
    missingok
    sharedscripts
    postrotate
        /bin/kill -HUP `cat /var/run/syslogd.pid 2> /dev/null` 2> /dev/null || true
    endscript
}
_EOF_
$pow mv -f /root/syslog /etc/logrotate.d/
$pow rm -Rf /root/bash1.txt


##################################
## Creating Groups for the user ##
##################################
$pow groupadd $g2
$pow groupadd $g3
$pow groupadd $g4

###############################
## Adding User on the server ##
###############################
$pow useradd $s1 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s1 && passwd -e $s1
$pow useradd $s2 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s2 && passwd -e $s2
$pow useradd $s3 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s3 && passwd -e $s3
$pow useradd $s4 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s4 && passwd -e $s4
$pow useradd $s5 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s5 && passwd -e $s5
$pow useradd $s6 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s6 && passwd -e $s6 
$pow useradd $s7 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s7 && passwd -e $s7
$pow useradd $s8 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s8 && passwd -e $s8
$pow useradd $s9 -g $g2 -m && echo -e "Bago@0123456!\nBago@0123456!" | passwd $s9 && passwd -e $s9


##########################
## System Hardening ctl ##
##########################
$pow cat > /root/sysctl.conf <<- _EOF_

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

vm.swappiness = 0
net.ipv4.neigh.default.gc_stale_time=120

# see details in https://help.aliyun.com/knowledge_detail/39428.html
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.default.arp_announce = 2
net.ipv4.conf.lo.arp_announce=2
net.ipv4.conf.all.arp_announce=2


# see details in https://help.aliyun.com/knowledge_detail/41334.html
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 1024
net.ipv4.tcp_synack_retries = 2
kernel.sysrq=1

## reduce time wait
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_fin_timeout = 5
_EOF_
$pow mv -f /root/sysctl.conf /etc/

################
## Log Rotate ##
################
$pow cat > /root/logrotate.conf<<- _EOF_
# see "man logrotate" for details
# rotate log files weekly
#weekly
daily

# keep 4 weeks worth of backlogs
rotate 31

# create new (empty) log files after rotating old ones
create

# use date as a suffix of the rotated file
dateext

# uncomment this if you want your log files compressed
compress

# RPM packages drop log rotation information into this directory
include /etc/logrotate.d

# no packages own wtmp and btmp -- we'll rotate them here
/var/log/wtmp {
    monthly
    create 0664 root utmp
    minsize 1M
    rotate 1
}

/var/log/btmp {
    missingok
    monthly
    create 0600 root utmp
    rotate 1
}

# system-specific logs may be also be configured here.
_EOF_
$pow mv -f /root/logrotate.conf /etc/

##################
## Login Server ##
##################
$pow cat > /root/login.defs<<- _EOF_
#
# Please note that the parameters in this configuration file control the
# behavior of the tools from the shadow-utils component. None of these
# tools uses the PAM mechanism, and the utilities that use PAM (such as the
# passwd command) should therefore be configured elsewhere. Refer to
# /etc/pam.d/system-auth for more information.
#

# *REQUIRED*
#   Directory where mailboxes reside, _or_ name of file, relative to the
#   home directory.  If you _do_ define both, MAIL_DIR takes precedence.
#   QMAIL_DIR is for Qmail
#
#QMAIL_DIR      Maildir
MAIL_DIR        /var/spool/mail
#MAIL_FILE      .mail

# Password aging controls:
#
#       PASS_MAX_DAYS   Maximum number of days a password may be used.
#       PASS_MIN_DAYS   Minimum number of days allowed between password changes.
#       PASS_MIN_LEN    Minimum acceptable password length.
#       PASS_WARN_AGE   Number of days warning given before a password expires.
#
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_MIN_LEN    5
PASS_WARN_AGE   7

#
# Min/max values for automatic uid selection in useradd
#
UID_MIN                  1000
UID_MAX                 60000
# System accounts
SYS_UID_MIN               201
SYS_UID_MAX               999

#
# Min/max values for automatic gid selection in groupadd
#
GID_MIN                  1000
GID_MAX                 60000
# System accounts
SYS_GID_MIN               201
SYS_GID_MAX               999

#
# If defined, this command is run when removing a user.
# It should remove any at/cron/print jobs etc. owned by
# the user to be removed (passed as the first argument).
#
#USERDEL_CMD    /usr/sbin/userdel_local

#
# If useradd should create home directories for users by default
# On RH systems, we do. This option is overridden with the -m flag on
# useradd command line.
#
CREATE_HOME     yes

# The permission mask is initialized to this value. If not specified,
# the permission mask will be initialized to 022.
UMASK           077

# This enables userdel to remove user groups if no members exist.
#
USERGROUPS_ENAB yes

# Use SHA512 to encrypt password.
ENCRYPT_METHOD SHA512
_EOF_
$pow mv -f /root/login.defs /etc/

echo " Do you want to install or configure IPtables? yes or no"
read n 
yes=$(echo $n | tr -s '[:upper:]' '[:lower:]')
if [[  "$n" = "yes"  ]] ; then

#####################
## Firewall Policy ##
#####################
$pow yum -y remove firewalld
$pow cat > /root/iptables-policy.sh <<- _EOF_
#!/bin/bash

/sbin/iptables -F
/sbin/iptables -X
/sbin/iptables -Z
/sbin/iptables -N LOGGING_DROP
/sbin/iptables -N LOGGING_ACCEPT

/sbin/iptables -A INPUT -i lo -j ACCEPT
/sbin/iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
/sbin/iptables -A INPUT -m state --state INVALID -j DROP ## drop invalid packets  
/sbin/iptables -A INPUT -i em1 -s 0.0.0.0/0 -p tcp -m tcp --dport 22 -j LOGGING_ACCEPT   
/sbin/iptables -A INPUT -i em1 -s 103.12.90.161/32 -j LOGGING_ACCEPT  
/sbin/iptables -A INPUT -i em1 -s 103.12.90.131/32 -j LOGGING_ACCEPT 
/sbin/iptables -A INPUT -i em1 -s 103.131.207.2/32 -j LOGGING_ACCEPT 
/sbin/iptables -A INPUT -i em1 -s 10.100.116.3/32 -j LOGGING_ACCEPT
/sbin/iptables -A INPUT -i em1 -s 10.100.116.4/32 -j LOGGING_ACCEPT
/sbin/iptables -A INPUT -i em1 -s 10.100.116.7/32 -j LOGGING_ACCEPT

/sbin/iptables -A INPUT -i em1 -s 192.168.0.0/16 -p tcp -m tcp --dport 19350 -j LOGGING_ACCEPT 
/sbin/iptables -A INPUT -i em1 -s 47.52.56.80/32 -p tcp -m tcp --dport 8787 -j ACCEPT
/sbin/iptables -A INPUT -i em1 -s 47.52.56.80/32 -p tcp -m tcp --dport 19350 -j ACCEPT
/sbin/iptables -A INPUT -i em1 -s 47.52.56.80/32 -p tcp -m tcp --dport 56666 -j ACCEPT
/sbin/iptables -A INPUT -i em1 -s 47.52.109.193/32 -p tcp -m tcp --dport 8787 -j ACCEPT
/sbin/iptables -A INPUT -i em1 -s 47.52.109.193/32 -p tcp -m tcp --dport 19350 -j ACCEPT
/sbin/iptables -A INPUT -i em1 -s 47.52.109.193/32 -p tcp -m tcp --dport 56666 -j ACCEPT
/sbin/iptables -A INPUT -i em1 -s 103.12.90.128/25 -p tcp -m tcp --dport 8787 -j ACCEPT
/sbin/iptables -A INPUT -i em1 -s 103.12.90.128/25 -p tcp -m tcp --dport 19350 -j ACCEPT
/sbin/iptables -A INPUT -i em1 -s 103.12.90.128/25 -p tcp -m tcp --dport 56666 -j ACCEPT

/sbin/iptables -A INPUT -i em1 -s 0.0.0.0/0 -m limit --limit 10/s --limit-burst 10 -p icmp -j ACCEPT ## allow ping

/sbin/iptables -A INPUT -i em1 -j DROP

## FORWARD ##
/sbin/iptables -A FORWARD -i em1 -j DROP

## OUTPUT ##
/sbin/iptables -A OUTPUT -m limit --limit 100/s --limit-burst 10 -j ACCEPT

## LOGGING ##
/sbin/iptables -A LOGGING_DROP -j LOG --log-prefix "DROP_LOG: " --log-level 7
/sbin/iptables -A LOGGING_DROP -j DROP
/sbin/iptables -A LOGGING_ACCEPT -j LOG --log-prefix "ACCEPT_LOG: " --log-level 7
/sbin/iptables -A LOGGING_ACCEPT -j ACCEPT
_EOF_

$pow chmod 777 /root/iptables-policy.sh && $pow sh /root/iptables-policy.sh
echo "If you want to edit your IPtables Policy go to /root/iptables-policy.sh"

else

echo "Just to inform you didn't install iptables harden settings"

fi

echo "Please Note the Message Below"
echo "The below is the user created by this automated script"
echo "santy.rafol"
echo "brando.caldetera"
echo "walter.alcantara"
echo "crispin.parungao"
echo "jack.ogania"
echo "eugene.duguran"
echo "philip.destura"
echo "yoeh.delosreyes"
echo "ishmael.cuyson"
echo "The default user password for all user created is Bago@0123456!"
$pow rm -Rf /root/automated-centos7-hardening 
