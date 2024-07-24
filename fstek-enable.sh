#!/bin/bash
rm -rf /var/fstek-enable.log; touch /var/fstek-enable.log
exec &>> /var/fstek-enable.log
current_date=$(date)
distr_var=$(cat /etc/*-release | grep DISTRIB_ID | sed 's/"//g')
distr_checker="DISTRIB_ID=AstraLinux"
echo "------------------------------------------------"
echo "$current_date"
if [ "$distr_var" == "$distr_checker" ]; then
        echo "This server runs Astra Linux OS"
	echo "sysctl updates:"
        sysctl kernel.kptr_restrict=2
        sysctl -w kernel.kptr_restrict=2 >> /etc/sysctl.conf
        sysctl net.core.bpf_jit_harden=2
        sysctl -w net.core.bpf_jit_harden=2 >> /etc/sysctl.conf
        sysctl fs.protected_fifos=2
        sysctl -w fs.protected_fifos=2 >> /etc/sysctl.conf
        sysctl fs.protected_regular=2
        sysctl -w fs.protected_regular=2 >> /etc/sysctl.conf
        sysctl kernel.yama.ptrace_scope=3
        sysctl -w kernel.yama.ptrace_scope=3 >> /etc/sysctl.conf
        sysctl dev.tty.ldisc_autoload=0
        sysctl -w dev.tty.ldisc_autoload=0 >> /etc/sysctl.conf
        sysctl vm.unprivileged_userfaultfd=0
        sysctl -w vm.unprivileged_userfaultfd=0 >> /etc/sysctl.conf
        sysctl user.max_user_namespace=0
        sysctl -w user.max_user_namespaces=0 >> /etc/sysctl.conf
        sysctl kernel.kexec_load_disabled=1
        sysctl -w kernel.kexec_load_disabled=1 >> /etc/sysctl.conf
	echo "------------------------------------------------"
        auth_var=$(cat /etc/pam.d/su | grep "auth required")
        checker_auth="auth required pam_wheel.su use_uid"
        if [ "$auth_var" == "$checker_auth" ]
        then
                echo "[auth required pam_wheel.su use_uid] is already enabled"
        else 
                echo "[auth required pam_wheel.su use_uid] added to config"
                echo "auth required pam_wheel.su use_uid" >> /etc/pam.d/su
        fi
	echo "------------------------------------------------"
        echo "Executable files permissions checker:"
	find /etc/cron* -maxdepth 1 -type f | while read line; do chmod 744 "$line"; echo "file: $line"; printf "permissions:" && ls -la "$line" | tr -d ' ' | cut -d'1' -f1; done
        find /usr/sbin/astra* -maxdepth 1 -type f | while read line; do chmod 744 "$line"; echo "file: $line"; printf "permissions:" && ls -la "$line" | tr -d ' ' | cut -d'1' -f1; done
	find /opt/kaspersky/klnagent64/sbin/*/* -maxdepth 1 -type f | while read line; do chmod -R 744 "$line"; echo "file: $line"; printf "permissions:" && ls -la "$line" | tr -d ' ' | cut -d'1' -f1; done 
	chmod -R 744 /opt/siem-jatoba/jatoba.log; echo "file: /opt/siem-jatoba/jatoba.log"; printf "permissions:" && ls -la /opt/siem-jatoba/jatoba.log | tr -d ' ' | cut -d'1' -f1;
	echo "------------------------------------------------"
	echo "GRUB settings updater:"
        sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="parsec.mac=0 quiet net.ifnames=0"/GRUB_CMDLINE_LINUX_DEFAULT="parsec.mac=0 quiet net.ifnames=0 quiet splash mitigations=auto,nosmt slab_nomerge init_on_alloc=1 iommu=force iommu.strict=1 iommu.passthrough=0 randomize_kstack_offset=1 debugfs=off tsx=off vsyscall=none debugfs=off"/' /etc/default/grub
	cat /etc/default/grub | grep "GRUB_CMDLINE_LINUX_DEFAULT"
	echo "------------------------------------------------"
	root_login_checker=$(cat /etc/ssh/sshd_config | grep "PermitRootLogin no")
        if [ "$root_login_checker" == "PermitRootLogin yes" ]
        then
		sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
	elif [ "$root_login_checker" == "" ]
	then
		echo "PermitRootLogin no" >> /etc/ssh/sshd_config
		echo "[PermitRootLogin no] added to config"
        else
		echo "[PermitRootLogin no] is already enabled"
        fi
fi
